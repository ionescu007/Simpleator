/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    partition.cpp

Abstract:

    This module implements initialization of the guest VA and its VM partition

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "sem.h"

typedef struct _MMPTE_HARDWARE
{
    union
    {
        struct
        {
            UINT64 Valid : 1;
            UINT64 Write : 1;
            UINT64 Owner : 1;
            UINT64 WriteThrough : 1;
            UINT64 CacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Dirty : 1;
            UINT64 LargePage : 1;
            UINT64 Available : 4;
            UINT64 PageFrameNumber : 36;
            UINT64 ReservedForHardware : 4;
            UINT64 ReservedForSoftware : 11;
            UINT64 NoExecute : 1;
        };
        UINT64 AsUlonglong;
    };
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;
C_ASSERT(sizeof(MMPTE_HARDWARE) == 8);

auto
SemVmCreateAddressSpace (
    _In_ PSEM_PARTITION Partition
    ) -> HRESULT
{
    PMMPTE_HARDWARE pml4;
    MMPTE_HARDWARE pdpte;

    //
    // Allocate the PML4
    //
    auto hr = SemAllocateGuestPrivateMemory(Partition,
                                            s_Pml4PhysicalAddress,
                                            512 * sizeof(*pml4) +
                                            512 * sizeof(pdpte),
                                            reinterpret_cast<PVOID*>(&pml4));
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Build a valid user-mode PML4E
    //
    pml4[0].AsUlonglong = 0;
    pml4[0].Valid = 1;
    pml4[0].Write = 1;
    pml4[0].Owner = 1;
    pml4[0].PageFrameNumber = (s_Pml4PhysicalAddress / USN_PAGE_SIZE) + 1;

    //
    // Build a valid user-mode 1GB PDPTE
    //
    pdpte.AsUlonglong = 0;
    pdpte.Valid = 1;
    pdpte.Write = 1;
    pdpte.Owner = 1;
    pdpte.LargePage = 1;

    //
    // Loop over the PDPT (PML3) minus the last 1GB
    //
    auto pdpt = &pml4[512];
    for (auto i = 0; i < 511; i++)
    {
        //
        // Set the PDPTE to the next valid 1GB of RAM, creating a 1:1 map
        //
        pdpt[i] = pdpte;
        pdpt[i].PageFrameNumber = (i * s_1GB) / USN_PAGE_SIZE;
    }

    //
    // We mark the last GB of RAM as off-limits
    // This corresponds to 0x0000`007FC0000000->0x0000`007FFFFFFFFF
    //
    pdpt[511].Valid = 0;
    return ERROR_SUCCESS;
}

auto
SemVmCreatePartition (
    _Outptr_ PSEM_PARTITION* Partition
    ) -> HRESULT
{
    WHV_PARTITION_PROPERTY prop;
    WHV_PARTITION_HANDLE partitionHandle;

    //
    // Create a Hyper-V External Partition
    //
    auto hr = WHvCreatePartition(&partitionHandle);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Allow a single processor
    //
    RtlZeroMemory(&prop, sizeof(prop));
    prop.ProcessorCount = 1;
    hr = WHvSetPartitionProperty(partitionHandle,
                                 WHvPartitionPropertyCodeProcessorCount,
                                 &prop,
                                 sizeof(prop));
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Activate the partition
    //
    hr = WHvSetupPartition(partitionHandle);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Return the partition and result
    //
    *Partition = reinterpret_cast<PSEM_PARTITION>(HeapAlloc(GetProcessHeap(),
                                                            0,
                                                            sizeof(**Partition)));
    if (*Partition == nullptr)
    {
        hr = HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
    }
    else
    {
        (*Partition)->PartitionHandle = partitionHandle;
    }
    return hr;
}

auto
SemVmInitializeAddressSpace (
    _In_ PSEM_PARTITION Partition,
    _In_ PWCHAR ImageFileName,
    _Out_ PULONG_PTR EntryPoint
    ) -> HRESULT
{
    PTHREAD_CONTROL_BLOCK threadBlock;
    WIN32_MEMORY_REGION_INFORMATION regionInfo;

    //
    // Allocate our thread control block, which includes the PEB, TEB and stack
    //
    auto hr = SemMmMapSharedMemory(Partition,
                                   s_TcbRegionAddress,
                                   sizeof(*threadBlock),
                                   reinterpret_cast<PVOID*>(&threadBlock));
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Capture address of TEB and PEB
    //
    auto teb = (PTEB)threadBlock->Teb;
    auto peb = (PPEB)threadBlock->Peb;
    auto ppb = (PRTL_USER_PROCESS_PARAMETERS)threadBlock->Ppb;
    auto currentPeb = NtCurrentTeb()->ProcessEnvironmentBlock;

    //
    // Configure basic TEB fields
    //
    auto tib = (PNT_TIB)teb;
    tib->Self = tib;
    teb->Reserved1[8] = (PVOID)(ULONG_PTR)GetCurrentProcessId();
    teb->Reserved1[9] = (PVOID)(ULONG_PTR)GetCurrentThreadId();
    teb->ProcessEnvironmentBlock = (PPEB)peb;

    //
    // Configure basic PEB fields, set global flags to show loader snaps
    //
    peb->ProcessParameters = (PRTL_USER_PROCESS_PARAMETERS)ppb;
    peb->Reserved9[10] = reinterpret_cast<PVOID>(1 | ((UINT64)2 << 32));
    peb->Reserved3[1] = reinterpret_cast<PVOID>(s_AppImageBase);
    peb->Reserved9[0] = threadBlock->ApiSetMap;

    //
    // Configure the basic PPB fields
    //
    *(PULONG)&ppb->Reserved1[4] = 4096;
    *(PULONG)&ppb->Reserved1[8] = 0x80004001;
    auto ppbPath = (PWCHAR)&threadBlock->Ppb[512];
    wcscpy_s(ppbPath, MAX_PATH, ImageFileName);
    RtlInitUnicodeString(&ppb->ImagePathName, ppbPath);
    RtlInitUnicodeString(&ppb->CommandLine, ppbPath);
    RtlInitUnicodeString((PUNICODE_STRING)&ppb->Reserved2[5], ppbPath);

    //
    // Get the size of the NLS Table Data
    //
    auto nlsData = currentPeb->Reserved9[7];
    auto bRes = QueryVirtualMemoryInformation(GetCurrentProcess(),
                                              nlsData,
                                              MemoryRegionInfo,
                                              &regionInfo,
                                              sizeof(regionInfo),
                                              NULL);
    if (bRes == FALSE)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Figure out the size of the tables by working backward
    //
    auto ansiSize = (ULONG_PTR)currentPeb->Reserved9[8] -
                    (ULONG_PTR)nlsData;
    auto oemSize = (ULONG_PTR)currentPeb->Reserved9[9] -
                   (ULONG_PTR)currentPeb->Reserved9[8];

    //
    // Copy all the data (ANSI, OEM, Unicode) and set PEB pointers
    //
    auto ansiTable = threadBlock->NlsTables;
    RtlCopyMemory(ansiTable, nlsData, regionInfo.RegionSize);
    peb->Reserved9[7] = ansiTable;
    peb->Reserved9[8] = ansiTable + ansiSize;
    peb->Reserved9[9] = ansiTable + ansiSize + oemSize;

    //
    // Get the size of the API Set Map and copy it
    //
    bRes = QueryVirtualMemoryInformation(GetCurrentProcess(),
                                         currentPeb->Reserved9[0],
                                         MemoryRegionInfo,
                                         &regionInfo,
                                         sizeof(regionInfo),
                                         NULL);
    if (bRes == FALSE)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    RtlCopyMemory(peb->Reserved9[0],
                  currentPeb->Reserved9[0],
                  regionInfo.RegionSize);

    //
    // Map shared user data page into the hypervisor partition
    //
    hr = SemMmMapSharedMemory(Partition,
                              reinterpret_cast<ULONG_PTR>(s_UserSharedData),
                              USN_PAGE_SIZE,
                              NULL);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Set the initial thread context
    //
    auto initialContext = (PCONTEXT)&threadBlock->InitialContext;
    initialContext->ContextFlags = CONTEXT_FULL;
    initialContext->Rdx = (DWORD64)peb;
    initialContext->Rsp = s_StackLimit - 8; // for alignment
    initialContext->SegSs = 0x2B;
    initialContext->SegCs = 0x33;
    initialContext->MxCsr = 0x1F80;
    initialContext->EFlags = 0x200;
    initialContext->FltSave.ControlWord = 0x27F;
    initialContext->FltSave.MxCsr = 0x1F80;
    initialContext->FltSave.MxCsr_Mask = 0xFFFF;

    //
    // Load the emulated EXE into the hypervisor guest
    //
    hr = SemLdrLoadImage(Partition,
                         ImageFileName,
                         s_AppImageBase,
                         NULL,
                         &initialContext->Rcx);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Load the system library into the hypervisor guest
    //
    return SemLdrLoadImage(Partition,
                           L"ntdll.dll",
                           s_NtdllBase,
                           &initialContext->Rip,
                           EntryPoint);
}

