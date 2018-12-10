/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    provider.cpp

Abstract:

    This module implements the RS5/19H1 System Call Provider for guest VMs.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "provider.h"

static SEM_PROVIDER_CALLBACKS s_SemCallbacks;

auto
HookNtMapViewOfSection (
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_ (*BaseAddress,
                  _Readable_bytes_ (*ViewSize)
                  _Writable_bytes_ (*ViewSize)
                  _Post_readable_byte_size_ (*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    )
{
    MEM_EXTENDED_PARAMETER extendedParam;
    MEM_ADDRESS_REQUIREMENTS reqs;
    auto status = STATUS_SUCCESS;

    //
    // Combinations of parameters that we don't wish to emulate aren't handled
    //
    if ((ZeroBits) || (CommitSize) || (InheritDisposition != 1))
    {
        status = STATUS_NOT_SUPPORTED;
        goto HookExit;
    }

    //
    // Nor are attempts to influence external host processes
    //
    if (ProcessHandle != GetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Check if this is a brand new commit
    //
    if (*BaseAddress == nullptr)
    {
        //
        // Ask the kernel to only allocate in the region of valid guest memory
        //
        reqs.Alignment = 0;
        reqs.LowestStartingAddress = s_LowestValidAddress;
        reqs.HighestEndingAddress = s_HighestValidAddress;
        extendedParam.Reserved = 0;
        extendedParam.Pointer = &reqs;
        extendedParam.Type = MemExtendedParameterAddressRequirements;
    }
    else if (!s_SemCallbacks.IsGuestMemory(*BaseAddress))
    {
        //
        // This is a commit on top of a reservation -- it must be guest memory
        //
        status = STATUS_CONFLICTING_ADDRESSES;
        goto HookExit;
    }

    //
    // Ask the kernel to do the map, noting that an existing reservation means
    // that we do not pass in extended parameters and simply re-use the base
    //
    status = NtMapViewOfSectionEx(SectionHandle,
                                  ProcessHandle,
                                  BaseAddress,
                                  SectionOffset,
                                  ViewSize,
                                  AllocationType,
                                  Win32Protect,
                                  (*BaseAddress == nullptr) ?
                                  &extendedParam : nullptr,
                                  (*BaseAddress == nullptr));

    //
    // We expect all image mappings to 'fail' with this code, due to relocation
    // records, which will then be fixed up by the loader on the guest side
    //
    if (status != STATUS_IMAGE_AT_DIFFERENT_BASE)
    {
        status = STATUS_NO_MEMORY;
        goto HookExit;
    }

    //
    // Finally, we must map the shared image in the GPA
    //
    auto hr = s_SemCallbacks.MapSharedImage(nullptr,
                                            (ULONG_PTR)*BaseAddress,
                                            *ViewSize);
    if (FAILED(hr)) DbgRaiseAssertionFailure();
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtAllocateVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_ (*BaseAddress,
                  _Readable_bytes_ (*RegionSize)
                  _Writable_bytes_ (*RegionSize)
                  _Post_readable_byte_size_ (*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    )
{
    MEM_EXTENDED_PARAMETER extendedParam;
    MEM_ADDRESS_REQUIREMENTS reqs;
    auto status = STATUS_SUCCESS;

    //
    // Combinations of parameters that we don't wish to emulate aren't handled
    //
    if (ZeroBits != 0)
    {
        status = STATUS_NOT_SUPPORTED;
        goto HookExit;
    }

    //
    // Nor are attempts to influence external host processes
    //
    if (ProcessHandle != GetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Check if this is a brand new commit
    //
    if (*BaseAddress == nullptr)
    {
        //
        // Ask the kernel to only allocate in the region of valid guest memory
        //
        reqs.Alignment = 0;
        reqs.LowestStartingAddress = s_LowestValidAddress;
        reqs.HighestEndingAddress = s_HighestValidAddress;
        extendedParam.Reserved = 0;
        extendedParam.Pointer = &reqs;
        extendedParam.Type = MemExtendedParameterAddressRequirements;
    }
    else if (!s_SemCallbacks.IsGuestMemory(*BaseAddress))
    {
        //
        // This is a commit on top of a reservation -- it must be guest memory
        //
        status = STATUS_CONFLICTING_ADDRESSES;
        goto HookExit;
    }

    //
    // Ask the kernel to allocate, noting that an existing reservation means
    // that we do not pass in extended parameters and simply re-use the base
    //
    status = NtAllocateVirtualMemoryEx(ProcessHandle,
                                       BaseAddress,
                                       RegionSize,
                                       AllocationType,
                                       Protect,
                                       (*BaseAddress == nullptr) ?
                                       &extendedParam : nullptr,
                                       (*BaseAddress == nullptr));
    if (!NT_SUCCESS(status))
    {
        goto HookExit;
    }

    //
    // If memory was actually committed, we must map it in the GPA
    //
    if (AllocationType & MEM_COMMIT)
    {
        auto hr = s_SemCallbacks.MapSharedMemory(nullptr,
                                                 reinterpret_cast<ULONG_PTR>(
                                                    *BaseAddress),
                                                 *RegionSize,
                                                 nullptr);
        if (FAILED(hr)) DbgRaiseAssertionFailure();
        goto HookExit;
    }

HookExit:
    return EncodeStatus(status);
}

auto
HookNtAllocateVirtualMemoryEx (
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_ (*BaseAddress,
                  _Readable_bytes_ (*RegionSize)
                  _Writable_bytes_ (*RegionSize)
                  _Post_readable_byte_size_ (*RegionSize)) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ParameterCount) PMEM_EXTENDED_PARAMETER Parameters,
    _In_ ULONG ParameterCount
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Check if the caller provided extended parameters
    //
    if (ParameterCount >= 1)
    {
        //
        // The only one we support are the address requirement paremeters
        //
        if (Parameters->Type == MemExtendedParameterAddressRequirements)
        {
            //
            // Which we override to specify that only guest memory must be used
            //
            auto reqs = reinterpret_cast<PMEM_ADDRESS_REQUIREMENTS>
                            (Parameters->Pointer);
            reqs->LowestStartingAddress = s_LowestValidAddress;
            reqs->HighestEndingAddress = s_HighestValidAddress;
        }
        else
        {
            status = STATUS_NOT_SUPPORTED;
            goto HookExit;
        }
    }
    else if (!s_SemCallbacks.IsGuestMemory(*BaseAddress))
    {
        //
        // This is a commit on top of a reservation -- it must be guest memory
        //
        status = STATUS_CONFLICTING_ADDRESSES;
        goto HookExit;
    }

    //
    // Attempts to influence external host processes are blocked
    //
    if (ProcessHandle != GetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Ask the kernel to allocate
    //
    status = NtAllocateVirtualMemoryEx(ProcessHandle,
                                       BaseAddress,
                                       RegionSize,
                                       AllocationType,
                                       PageProtection,
                                       Parameters,
                                       ParameterCount);
    if (!NT_SUCCESS(status))
    {
        goto HookExit;
    }

    //
    // If memory was actually committed, we must map it in the GPA
    //
    if (AllocationType & MEM_COMMIT)
    {
        auto hr = s_SemCallbacks.MapSharedMemory(nullptr,
                                                 reinterpret_cast<ULONG_PTR>
                                                     (*BaseAddress),
                                                 *RegionSize,
                                                 nullptr);
        if (FAILED(hr)) DbgRaiseAssertionFailure();
        goto HookExit;
    }

HookExit:
    return EncodeStatus(status);
}

auto
HookNtFreeVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    )
{
    auto status = STATUS_SUCCESS;

    //
    // If this is the loader trying to unmap the old PPB, make this a no-op
    //
    if (*BaseAddress == (PVOID)((ULONG_PTR)s_SemCallbacks.GetCurrentTeb()->ProcessEnvironmentBlock + 0x1000))
    {
        goto HookExit;
    }

    //
    // Only guest memory should be freed
    //
    if (!s_SemCallbacks.IsGuestMemory(*BaseAddress))
    {
        status = STATUS_UNABLE_TO_FREE_VM;
        goto HookExit;
    }

    //
    // Attempts to influence external host processes are blocked
    //
    if (ProcessHandle != GetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Unmap the respective GPA
    //
    auto hr = s_SemCallbacks.UnmapSharedMemory(nullptr,
                                               reinterpret_cast<ULONG_PTR>
                                                   (*BaseAddress),
                                               *RegionSize,
                                               nullptr);
    if (FAILED(hr)) DbgRaiseAssertionFailure();

    //
    // And then issue the call to the host kernel to free the VA
    //
    status = NtFreeVirtualMemory(ProcessHandle,
                                 BaseAddress,
                                 RegionSize,
                                 FreeType);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtProtectVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Only guest memory should be protected
    //
    if (!s_SemCallbacks.IsGuestMemory(*BaseAddress))
    {
        status = STATUS_INVALID_PAGE_PROTECTION;
        goto HookExit;
    }

    //
    // Attempts to influence external host processes are blocked
    //
    if (ProcessHandle != GetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Issue the call to the host kernel to protect the VA
    //
    status = NtProtectVirtualMemory(ProcessHandle,
                                    BaseAddress,
                                    RegionSize,
                                    NewProtect,
                                    OldProtect);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtQueryDebugFilterState (
    _In_ ULONG ComponentId,
    _In_ ULONG Level
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Get the host debug filter state
    //
    status = NtQueryDebugFilterState(ComponentId, Level);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtDuplicateObject (
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Attempts to influence external host processes are blocked
    //
    if ((SourceProcessHandle != GetCurrentProcess()) ||
        (TargetProcessHandle != GetCurrentProcess()))
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Ask the kernel to duplicate the handle
    //
    status = NtDuplicateObject(SourceProcessHandle,
                               SourceHandle,
                               TargetProcessHandle,
                               TargetHandle,
                               DesiredAccess,
                               HandleAttributes,
                               Options);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtQueryVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Only guest memory should be queried, unless this is a working set dump
    //
    if (!(s_SemCallbacks.IsGuestMemory(BaseAddress)) &&
        (MemoryInformationClass != 4))
    {
        status = STATUS_MEMORY_NOT_ALLOCATED;
        goto HookExit;
    }

    //
    // Attempts to influence external host processes are blocked
    //
    if (ProcessHandle != GetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Call the host kernel to query the VAD
    //
    status = NtQueryVirtualMemory(ProcessHandle,
                                  BaseAddress,
                                  MemoryInformationClass,
                                  MemoryInformation,
                                  MemoryInformationLength,
                                  ReturnLength);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtQueryInformationProcess (
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Attempts to influence external host processes are blocked
    //
    if (ProcessHandle != GetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Only handle these 2 basic classes
    //
    if ((ProcessInformationClass != ProcessBasicInformation) &&
        (ProcessInformationClass != ProcessCookie))
    {
        status = STATUS_INVALID_INFO_CLASS;
        goto HookExit;
    }

    //
    // Call the host kernel to get information on the process
    //
    status = NtQueryInformationProcess(ProcessHandle,
                                       ProcessInformationClass,
                                       ProcessInformation,
                                       ProcessInformationLength,
                                       ReturnLength);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtTerminateProcess (
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Attempts to influence external host processes are blocked
    //
    if ((ProcessHandle) && (ProcessHandle != GetCurrentProcess()))
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Kill the host process that represents the guest
    //
    status = NtTerminateProcess(ProcessHandle, ExitStatus);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtQuerySystemInformation (
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_to_opt_(SystemInformationLength,
                              *ReturnLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    )
{
    auto status = STATUS_INVALID_INFO_CLASS;

    //
    // Special fast path for the loader check done on RS5+
    //
    if (SystemInformationClass == SystemHypervisorSharedPageInformation)
    {
        return EncodeFailureOk(status);
    }

    //
    // Special fast path which helps the guest environment use the right limits
    //
    if (SystemInformationClass == SystemRangeStartInformation)
    {
        *reinterpret_cast<PULONG_PTR>(SystemInformation) = s_256GB;
        status = STATUS_SUCCESS;
        goto HookExit;
    }

    //
    // We only implement the information classes below
    //
    if ((SystemInformationClass != SystemBasicInformation) &&
        (SystemInformationClass != SystemFlushInformation) &&
        (SystemInformationClass != SystemEmulationBasicInformation) &&
        (SystemInformationClass != SystemNumaProcessorMap) &&
        (SystemInformationClass != SystemTimeOfDayInformation))
    {
        status = STATUS_INVALID_INFO_CLASS;
        goto HookExit;
    }

    //
    // Call the host kernel to get the information
    //
    status = NtQuerySystemInformation(SystemInformationClass,
                                      SystemInformation,
                                      SystemInformationLength,
                                      ReturnLength);

HookExit:
    return EncodeStatus(status);
}

auto
HookNtSetInformationProcess (
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Attempts to influence external host processes are blocked
    //
    if (ProcessHandle != GetCurrentProcess())
    {
        status = STATUS_ACCESS_DENIED;
        goto HookExit;
    }

    //
    // Only the console host owner is allowed to be set
    //
    if (ProcessInformationClass != ProcessOwnerInformation)
    {
        status = STATUS_INVALID_INFO_CLASS;
        goto HookExit;
    }

    //
    // Call the host kernel to set the information
    //
    status = NtSetInformationProcess(ProcessHandle,
                                     ProcessInformationClass,
                                     ProcessInformation,
                                     ProcessInformationLength);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtQueryVolumeInformationFile (
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FsInformation,
    _In_ ULONG Length,
    _In_ FS_INFORMATION_CLASS FsInformationClass
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Only attribute information can be queried
    //
    if (FsInformationClass != FileFsAttributeInformation)
    {
        status = STATUS_INVALID_INFO_CLASS;
        goto HookExit;
    }

    //
    // Call the host kernel to query the information
    // @TODO: Add handle tracking
    //
    status = NtQueryVolumeInformationFile(FileHandle,
                                          IoStatusBlock,
                                          FsInformation,
                                          Length,
                                          FsInformationClass);

    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtQueryPerformanceCounter (
    _Out_ PLARGE_INTEGER PerformanceCounter,
    _Out_opt_ PLARGE_INTEGER PerformanceFrequency
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Get the host QPC frequency and value
    //
    status = NtQueryPerformanceCounter(PerformanceCounter,
                                       PerformanceFrequency);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtOpenFile (
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Open the file requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtOpenFile(FileHandle,
                        DesiredAccess,
                        ObjectAttributes,
                        IoStatusBlock,
                        ShareAccess,
                        OpenOptions);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtCreateFile (
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Create the file requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtCreateFile(FileHandle,
                          DesiredAccess,
                          ObjectAttributes,
                          IoStatusBlock,
                          AllocationSize,
                          FileAttributes,
                          ShareAccess,
                          CreateDisposition,
                          CreateOptions,
                          EaBuffer,
                          EaLength);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtDeviceIoControlFile (
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Send the IOCTL to the device requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtDeviceIoControlFile(FileHandle,
                                   Event,
                                   ApcRoutine,
                                   ApcContext,
                                   IoStatusBlock,
                                   IoControlCode,
                                   InputBuffer,
                                   InputBufferLength,
                                   OutputBuffer,
                                   OutputBufferLength);
    if (!NT_SUCCESS(status))
    {
        //
        // If this is a CONDRV message that's failing with an unsupported code
        // then allow the failure, as this is expected even on a real host
        //
        if ((IoControlCode == 0x00500016) && (status == 0xC00700BB))
        {
            return EncodeFailureOk(status);
        }
    }
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtWriteFile (
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Write into the file requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtWriteFile(FileHandle,
                         Event,
                         ApcRoutine,
                         ApcContext,
                         IoStatusBlock,
                         Buffer,
                         Length,
                         ByteOffset,
                         Key);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtCreateEvent (
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Create the event requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtCreateEvent(EventHandle,
                           DesiredAccess,
                           ObjectAttributes,
                           EventType,
                           InitialState);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtSetEvent (
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Signal the event requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtSetEvent(EventHandle, PreviousState);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtOpenDirectoryObject (
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Open the object directory requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtOpenDirectoryObject(DirectoryHandle,
                                   DesiredAccess,
                                   ObjectAttributes);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtOpenSymbolicLinkObject (
    _Out_ PHANDLE LinkHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Open the symbolic link object requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtOpenSymbolicLinkObject(LinkHandle,
                                      DesiredAccess,
                                      ObjectAttributes);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtQuerySymbolicLinkObject (
    _In_ HANDLE LinkHandle,
    _Inout_ PUNICODE_STRING LinkTarget,
    _Out_opt_ PULONG ReturnedLength
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Query the symbolic link object requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtQuerySymbolicLinkObject(LinkHandle, LinkTarget, ReturnedLength);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtOpenSection (
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Open the section object requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtClose (
    _In_ HANDLE Handle
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Close the handle requested by the guest
    // @TODO: Add handle tracking
    //
    status = NtClose(Handle);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookNtContinue (
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN TestAlert
    )
{
    UNREFERENCED_PARAMETER(TestAlert);

    //
    // Switch the CPU back to user mode and the specified program counter/stack
    //
    s_SemCallbacks.SwitchMode(ContextRecord->Rcx,
                              ContextRecord->Rdx,
                              ContextRecord->EFlags,
                              ContextRecord->Rsp,
                              ContextRecord->Rip,
                              ContextRecord->SegCs,
                              ContextRecord->SegSs);

    //
    // Use a specialized return code to avoid resuming to the original context
    //
    return EncodeNoResume(STATUS_SUCCESS);
}

auto
HookNtRaiseException (
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord,
    _In_ BOOLEAN FirstChance
    )
{
    PCHAR buffer;
    INT bufferSize;
    auto status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(FirstChance);

    //
    // The only exception we handle is a DebugPrint exception
    //
    if (ExceptionRecord->ExceptionCode != DBG_PRINTEXCEPTION_C)
    {
        status = STATUS_NOT_IMPLEMENTED;
        goto HookExit;
    }

    //
    // Extract the buffer and its size, then print it out
    //
    buffer = reinterpret_cast<PCHAR>(ExceptionRecord->ExceptionInformation[1]);
    bufferSize = static_cast<INT>(ExceptionRecord->ExceptionInformation[0]) - 1;
    s_SemCallbacks.DebugPrint(buffer, bufferSize);

    //
    // Restore the CPU state to resume after the debug exception
    //
    s_SemCallbacks.RestoreException(ContextRecord->Rsp,
                                    ContextRecord->Rbp,
                                    ContextRecord->Rsi,
                                    ContextRecord->Rdi,
                                    ContextRecord->Rbx,
                                    reinterpret_cast<UINT64>
                                        (ExceptionRecord->ExceptionAddress));
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

auto
HookDebugPrint (
    _In_ PCHAR Buffer,
    _In_ INT Length
    )
{
    auto status = STATUS_SUCCESS;

    //
    // Print it out the string
    //
    s_SemCallbacks.DebugPrint(Buffer, Length);
    goto HookExit;

HookExit:
    return EncodeStatus(status);
}

typedef struct _SEM_SYSCALL_PROVIDER_ENTRY
{
    USHORT CallId;
    UCHAR Arguments;
    PVOID Function;
    PCHAR FunctionName;
} SEM_SYSCALL_PROVIDER_ENTRY, *PSEM_SYSCALL_PROVIDER_ENTRY;
static SEM_SYSCALL_PROVIDER_ENTRY s_Win10RS5_Index_Table[] =
{
    //
    // Security Cookie Setup
    //
    {0x31, 2, HookNtQueryPerformanceCounter, "NtQueryPerformanceCounter"},

    //
    // Initial querying of .MRDATA
    //
    {0x36, 4, HookNtQuerySystemInformation, "NtQuerySystemInformation"},
    {0x50, 5, HookNtProtectVirtualMemory, "NtProtectVirtualMemory"},
    {0x19, 5, HookNtQueryInformationProcess, "NtQueryInformationProcess"},
    {0x23, 6, HookNtQueryVirtualMemory, "NtQueryVirtualMemory"},

    //
    // Initial IFEO setup
    //
    {0x12, 3, nullptr, "NtOpenKey"},

    //
    // First DebugPrint
    //
    {0x13A, 2, HookNtQueryDebugFilterState, "NtQueryDebugFilterState"},

    //
    // Heap setup
    //
    {0x153, 6, nullptr, "NtQuerySecurityAttributesToken"},
    {0x74, 7, HookNtAllocateVirtualMemoryEx, "NtAllocateVirtualMemoryEx"},
    {0x18, 6, HookNtAllocateVirtualMemory, "NtAllocateVirtualMemory"},
    {0x1E, 4, HookNtFreeVirtualMemory, "NtFreeVirtualMemory"},

    //
    // Create loader event
    //
    {0x48, 5, HookNtCreateEvent, "NtCreateEvent"},

    //
    // Worker Pool
    //
    {0xC4, 3, nullptr, "NtCreateWaitCompletionPacket"},
    {0xF, 1, HookNtClose, "NtClose"},
    {0x15A, 6, nullptr, "NtQuerySystemInformationEx"},

    //
    // Known DLL Validation
    //
    {0x58, 3, HookNtOpenDirectoryObject, "NtOpenDirectoryObject"},
    {0x127, 3, HookNtOpenSymbolicLinkObject, "NtOpenSymbolicLinkObject"},
    {0x157, 3, HookNtQuerySymbolicLinkObject, "NtQuerySymbolicLinkObject"},

    //
    // Initial LdrpLogDbgPrint
    //
    {0x15F, 3, HookNtRaiseException, "NtRaiseException"},

    //
    // Setting up current path
    //
    {0x33, 6, HookNtOpenFile, "NtOpenFile"},
    {0x49, 5, HookNtQueryVolumeInformationFile, "NtQueryVolumeInformationFile"},

    //
    // Signal loader event
    //
    {0xE, 2, HookNtSetEvent, "NtSetEvent"},
    {0x25, 5, nullptr, "NtQueryInformationThread"},

    //
    // Beginning DLL load of kernel32/base
    //
    {0x37, 3, HookNtOpenSection, "NtOpenSection"},
    {0x28, 10, HookNtMapViewOfSection, "NtMapViewOfSection"},
    {0x4C, 2, nullptr, "NtApphelpCacheControl"},

    //
    // Kernelbase init
    //
    {0x55, 11, HookNtCreateFile, "NtCreateFile"},
    {0x7, 10, HookNtDeviceIoControlFile, "NtDeviceIoControlFile"},
    {0x3C, 7, HookNtDuplicateObject, "NtDuplicateObject"},
    {0x1C, 4, HookNtSetInformationProcess, "NtSetInformationProcess"},

    //
    // RS5 Hotpatch Support
    //
    {0x197, 6, nullptr, "NtSetInformationVirtualMemory"},

    //
    // Init finished
    //
    {0x1B9, 0, nullptr, "NtTestAlert"},
    {0x43, 1, HookNtContinue, "NtContinue"},

    //
    // Print to console
    //
    {0x8, 9, HookNtWriteFile, "NtWriteFile"},

    //
    // Exit
    //
    {0x2C, 2, HookNtTerminateProcess, "NtTerminateProcess"},
};
static SEM_SYSCALL_PROVIDER_ENTRY s_Win1019H1_Index_Table[] =
{
    //
    // Security Cookie Setup
    //
    {0x31, 2, HookNtQueryPerformanceCounter, "NtQueryPerformanceCounter"},

    //
    // Initial querying of .MRDATA
    //
    {0x36, 4, HookNtQuerySystemInformation, "NtQuerySystemInformation"},
    {0x50, 5, HookNtProtectVirtualMemory, "NtProtectVirtualMemory"},
    {0x19, 5, HookNtQueryInformationProcess, "NtQueryInformationProcess"},
    {0x23, 6, HookNtQueryVirtualMemory, "NtQueryVirtualMemory"},

    //
    // Initial IFEO setup
    //
    {0x12, 3, nullptr, "NtOpenKey"},

    //
    // First DebugPrint
    //
    {0x13B, 2, HookNtQueryDebugFilterState, "NtQueryDebugFilterState"},

    //
    // Heap setup
    //
    {0x154, 6, nullptr, "NtQuerySecurityAttributesToken"},
    {0x74, 7, HookNtAllocateVirtualMemoryEx, "NtAllocateVirtualMemoryEx"},
    {0x18, 6, HookNtAllocateVirtualMemory, "NtAllocateVirtualMemory"},
    {0x1E, 4, HookNtFreeVirtualMemory, "NtFreeVirtualMemory"},

    //
    // Create loader event
    //
    {0x48, 5, HookNtCreateEvent, "NtCreateEvent"},

    //
    // Worker Pool
    //
    {0xC5, 3, nullptr, "NtCreateWaitCompletionPacket"},
    {0xF, 1, HookNtClose, "NtClose"},
    {0x15B, 6, nullptr, "NtQuerySystemInformationEx"},

    //
    // Known DLL Validation
    //
    {0x58, 3, HookNtOpenDirectoryObject, "NtOpenDirectoryObject"},
    {0x128, 3, HookNtOpenSymbolicLinkObject, "NtOpenSymbolicLinkObject"},
    {0x158, 3, HookNtQuerySymbolicLinkObject, "NtQuerySymbolicLinkObject"},

    //
    // Initial LdrpLogDbgPrint
    //
    {0x160, 3, HookNtRaiseException, "NtRaiseException"},

    //
    // Setting up current path
    //
    {0x33, 6, HookNtOpenFile, "NtOpenFile"},
    {0x49, 5, HookNtQueryVolumeInformationFile, "NtQueryVolumeInformationFile"},

    //
    // Signal loader event
    //
    {0xE, 2, HookNtSetEvent, "NtSetEvent"},
    {0x25, 5, nullptr, "NtQueryInformationThread"},

    //
    // Beginning DLL load of kernel32/base
    //
    {0x37, 3, HookNtOpenSection, "NtOpenSection"},
    {0x28, 10, HookNtMapViewOfSection, "NtMapViewOfSection"},
    {0x4C, 2, nullptr, "NtApphelpCacheControl"},

    //
    // Kernelbase init
    //
    {0x55, 11, HookNtCreateFile, "NtCreateFile"},
    {0x7, 10, HookNtDeviceIoControlFile, "NtDeviceIoControlFile"},
    {0x3C, 7, HookNtDuplicateObject, "NtDuplicateObject"},
    {0x1C, 4, HookNtSetInformationProcess, "NtSetInformationProcess"},

    //
    // RS5 Hotpatch Support
    //
    {0x198, 6, nullptr, "NtSetInformationVirtualMemory"},

    //
    // Init finished
    //
    {0x1BA, 0, nullptr, "NtTestAlert"},
    {0x43, 1, HookNtContinue, "NtContinue"},

    //
    // Print to console
    //
    {0x8, 9, HookNtWriteFile, "NtWriteFile"},

    //
    // Exit
    //
    {0x2C, 2, HookNtTerminateProcess, "NtTerminateProcess"},

};

EXTERN_C
VOID
SemRegisterSystemCallProvider (
    _In_ CONST SEM_PROVIDER_CALLBACKS* SemCallbacks
    )
{
    auto static s_BuildNumber = *reinterpret_cast<PULONG>(0x7FFE0260);

    //
    // Capture the callbacks locally
    //
    s_SemCallbacks = *SemCallbacks;

    //
    // Check if this is RS5 (1809) or 19H1 (1903)
    // @TODO: Once 19H2 is out, this should be made better
    //
    for (auto &entry : (s_BuildNumber == 17763) ?
                        s_Win10RS5_Index_Table : s_Win1019H1_Index_Table)
    {
        //
        // Register all of our system calls
        //
        s_SemCallbacks.RegisterSystemCall(entry.CallId,
                                          entry.Arguments,
                                          entry.Function,
                                          entry.FunctionName);
    }

    //
    // Register the debug trap
    //
    s_SemCallbacks.RegisterDebugTrap(1, 2, HookDebugPrint);
}
