/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    ntemu.h

Abstract:

    This header defines the native system call function types for RS5/19H1.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once

EXTERN_C_START

#define ProcessCookie                           0x24
#define FileFsAttributeInformation              0x04
#define ProcessOwnerInformation                 0x31
#define SystemEmulationBasicInformation         0x3E
#define SystemHypervisorSharedPageInformation   0xC5
#define SystemNumaProcessorMap                  0x37
#define SystemRangeStartInformation             0x32
#define SystemFlushInformation                  0xC0

typedef ULONG SECTION_INHERIT;
typedef ULONG EVENT_TYPE;
typedef ULONG FS_INFORMATION_CLASS;
typedef ULONG MEMORY_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateEvent (
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
);

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateProcess (
    _In_opt_ HANDLE ProcessHandle,
    _In_ NTSTATUS ExitStatus
);

NTSYSAPI
NTSTATUS
NTAPI
NtWriteFile (
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSection (
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryVolumeInformationFile (
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FsInformation,
    _In_ ULONG Length,
    _In_ FS_INFORMATION_CLASS FsInformationClass
);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryPerformanceCounter (
    _Out_ PLARGE_INTEGER PerformanceCounter,
    _Out_opt_ PLARGE_INTEGER PerformanceFrequency
);

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemoryEx (
    _In_opt_ HANDLE Process,
    _In_opt_ PVOID* BaseAddress,
    _In_ SIZE_T* RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ParameterCount) MEM_EXTENDED_PARAMETER* Parameters,
    _In_ ULONG ParameterCount
);

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationProcess (
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);

NTSYSAPI
NTSTATUS
NTAPI
NtSetEvent (
    _In_ HANDLE EventHandle,
    _Out_opt_ PLONG PreviousState
);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenDirectoryObject (
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSAPI
NTSTATUS
NTAPI
NtMapViewOfSectionEx (
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_ (*BaseAddress,
                  _Readable_bytes_ (*ViewSize)
                  _Writable_bytes_ (*ViewSize)
                  _Post_readable_byte_size_ (*ViewSize)) PVOID *BaseAddress,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect,
    _Inout_updates_opt_(ParameterCount) MEM_EXTENDED_PARAMETER* Parameters,
    _In_ ULONG ParameterCount
);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

NTSYSAPI
NTSTATUS
NTAPI
NtDuplicateObject (
    _In_ HANDLE SourceProcessHandle,
    _In_ HANDLE SourceHandle,
    _In_opt_ HANDLE TargetProcessHandle,
    _Out_opt_ PHANDLE TargetHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Options
);

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySymbolicLinkObject (
    _In_ HANDLE LinkHandle,
    _Inout_ PUNICODE_STRING LinkTarget,
    _Out_opt_ PULONG ReturnedLength
);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryDebugFilterState (
    _In_ ULONG ComponentId,
    _In_ ULONG Level
);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSymbolicLinkObject (
    _Out_ PHANDLE LinkHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

EXTERN_C_END

