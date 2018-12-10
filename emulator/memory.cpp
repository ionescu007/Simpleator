/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    memory.cpp

Abstract:

    This module implements the main GPA<->HVA handling functions for the guest

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "sem.h"

EXTERN_C void __std_terminate(void) { }
EXTERN_C void __CxxFrameHandler3(void) { }

auto
SemAllocateGuestPrivateMemory (
    _In_ PSEM_PARTITION Partition,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size,
    _Outptr_ PVOID* HostVa
    ) -> HRESULT
{
    //
    // Allocate top-down as to not disturb the guest VA
    //
    *HostVa = VirtualAlloc2(GetCurrentProcess(),
                            NULL,
                            Size,
                            MEM_COMMIT | MEM_TOP_DOWN,
                            PAGE_READWRITE,
                            NULL,
                            0);
    if (*HostVa == nullptr)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Map it into the partition
    //
    return WHvMapGpaRange(Partition->PartitionHandle,
                          *HostVa,
                          GuestVa,
                          Size,
                          WHvMapGpaRangeFlagRead |
                          WHvMapGpaRangeFlagWrite);
}

auto
SemMmMapGuestImage (
    _In_opt_ PSEM_PARTITION Partition,
    _In_ HANDLE ImageHandle,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size,
    _Outptr_ PVOID* HostVa
    ) -> HRESULT
{
    //
    // If no partition was passed in, use the current partition
    //
    if (Partition == nullptr)
    {
        Partition = SemPartitionFromVp(t_CurrentVp);
    }

    //
    // Map the image at the desired base address
    //
    *HostVa = MapViewOfFile3(ImageHandle,
                             GetCurrentProcess(),
                             reinterpret_cast<PVOID>(GuestVa),
                             0,
                             0,
                             MEM_DIFFERENT_IMAGE_BASE_OK,
                             PAGE_EXECUTE_READ,
                             NULL,
                             NULL);
    if (*HostVa == nullptr)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Map the image section into the partition. TODO: Unmap on failure?
    //
    auto hr = WHvMapGpaRange(Partition->PartitionHandle,
                             *HostVa,
                             GuestVa,
                             Size,
                             WHvMapGpaRangeFlagRead |
                             WHvMapGpaRangeFlagWrite |
                             WHvMapGpaRangeFlagExecute);

    return hr;
}

auto
SemMmMapSharedImage (
    _In_opt_ PSEM_PARTITION Partition,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size
    ) -> HRESULT
{
    //
    // If no partition was passed in, use the current partition
    //
    if (Partition == nullptr)
    {
        Partition = SemPartitionFromVp(t_CurrentVp);
    }

    //
    // Map it into the partition
    //
    return WHvMapGpaRange(Partition->PartitionHandle,
                          reinterpret_cast<PVOID>(GuestVa),
                          GuestVa,
                          Size,
                          WHvMapGpaRangeFlagRead |
                          WHvMapGpaRangeFlagWrite |
                          WHvMapGpaRangeFlagExecute);
}

auto
SemMmUnmapSharedMemory (
    _In_opt_ PSEM_PARTITION Partition,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size,
    _In_opt_ PVOID HostVa
    ) -> HRESULT
{
    //
    // If no partition was passed in, use the current partition
    //
    if (Partition == nullptr)
    {
        Partition = SemPartitionFromVp(t_CurrentVp);
    }

    //
    // Unmap the range from the virtual machine
    //
    auto hr = WHvUnmapGpaRange(Partition->PartitionHandle, GuestVa, Size);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Do we own the host allocation as well?
    //
    if (HostVa != nullptr)
    {
        //
        // Free it
        //
        auto bRes = VirtualFreeEx(GetCurrentProcess(), HostVa, 0, MEM_RELEASE);
        if (bRes == FALSE)
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    //
    // All done
    //
    return hr;
}

auto
SemMmMapSharedMemory (
    _In_opt_ PSEM_PARTITION Partition,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size,
    _Outptr_opt_ PVOID* HostVa
    ) -> HRESULT
{
    //
    // If no partition was passed in, use the current partition
    //
    if (Partition == nullptr)
    {
        Partition = SemPartitionFromVp(t_CurrentVp);
    }

    //
    // Carve out a piece from our reservation
    //
    if (HostVa != nullptr)
    {
        *HostVa = VirtualAlloc2(GetCurrentProcess(),
                                reinterpret_cast<PVOID>(GuestVa),
                                Size,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE,
                                NULL,
                                0);
        if (*HostVa == nullptr)
        {
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    //
    // Map it into the partition. TODO: Unmap on failure?
    //
    return WHvMapGpaRange(Partition->PartitionHandle,
                          reinterpret_cast<PVOID>(GuestVa),
                          GuestVa,
                          Size,
                          WHvMapGpaRangeFlagRead |
                          WHvMapGpaRangeFlagWrite);
}
