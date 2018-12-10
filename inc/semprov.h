/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    semprov.h

Abstract:

    This header defines the interface for Simple Emulator System Call Providers

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

//
// System Call Provider hooks return this complex status to encode actions and result
//
typedef enum _SEM_STATUS_FLAGS
{
    SemNoFlags = 0x0,
    SemDoNotResume = 0x1,
    SemFailureIsExpected = 0x2
} SEM_STATUS_FLAGS;
typedef union _SEM_SYSCALL_STATUS
{
    struct
    {
        NTSTATUS Status;
        SEM_STATUS_FLAGS Flags;
    };
    ULONG64 StatusValue;
} SEM_SYSCALL_STATUS;

auto FORCEINLINE EncodeNoResume (_In_ NTSTATUS Status)  { return SEM_SYSCALL_STATUS{ Status, SemDoNotResume };          }
auto FORCEINLINE EncodeFailureOk (_In_ NTSTATUS Status) { return SEM_SYSCALL_STATUS{ Status, SemFailureIsExpected };    }
auto FORCEINLINE EncodeStatus (_In_ NTSTATUS Status)    { return SEM_SYSCALL_STATUS{ Status, SemNoFlags };              }

//
// Virtual Processor Functions
//
auto
SemVpSwitchMode (
    _In_ UINT64 Rcx,
    _In_ UINT64 Rdx,
    _In_ UINT64 Flags,
    _In_ UINT64 StackPointer,
    _In_ UINT64 ProgramCounter,
    _In_ UINT16 CodeSeg,
    _In_ UINT16 StackSeg
)->HRESULT;

auto
SemVpRestoreExceptionContext (
    _In_ UINT64 Rsp,
    _In_ UINT64 Rbp,
    _In_ UINT64 Rsi,
    _In_ UINT64 Rdi,
    _In_ UINT64 Rbx,
    _In_ UINT64 Rcx
)->HRESULT;

auto
SemVpGetCurrentTeb (
    VOID
)->PTEB;

//
// Memory Functions
//
auto
SemMmMapGuestImage (
    _In_ PSEM_PARTITION Partition,
    _In_ HANDLE ImageHandle,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size,
    _Outptr_ PVOID* HostVa
)->HRESULT;

auto
SemMmMapSharedMemory (
    _In_ PSEM_PARTITION Partition,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size,
    _Outptr_opt_ PVOID* HostVa
)->HRESULT;

auto
SemMmMapSharedImage (
    _In_ PSEM_PARTITION Partition,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size
)->HRESULT;

auto
SemMmUnmapSharedMemory (
    _In_ PSEM_PARTITION Partition,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size,
    _In_opt_ PVOID HostVa
)->HRESULT;

auto
IsGuestMemoryPtr (
    _In_ PVOID Address
) -> bool;

//
// Debugging Functions
//
auto
SemVmDebugPrint (
    _In_ PCHAR Buffer,
    _In_ ULONG Length
)->VOID;

auto
SemVmError (
    _In_ PCHAR ErrorString,
    ...
)->VOID;

//
// System Call Registration API
//
auto
SemRegisterSystemCall (
    _In_ USHORT Index,
    _In_ UCHAR Arguments,
    _In_opt_ PVOID Function,
    _In_ PCHAR FunctionName
)->VOID;

auto
SemRegisterDebugTrap (
    _In_ USHORT Index,
    _In_ UCHAR Arguments,
    _In_ PVOID Function
)->VOID;

//
// APIs exposed by emulator for the provider
//
typedef struct _SEM_PROVIDER_CALLBACKS
{
    decltype(&IsGuestMemoryPtr) IsGuestMemory;
    decltype(&SemMmMapSharedImage) MapSharedImage;
    decltype(&SemMmMapSharedMemory) MapSharedMemory;
    decltype(&SemMmUnmapSharedMemory) UnmapSharedMemory;
    decltype(&SemRegisterSystemCall) RegisterSystemCall;
    decltype(&SemRegisterDebugTrap) RegisterDebugTrap;
    decltype(&SemVmDebugPrint) DebugPrint;
    decltype(&SemVmError) TraceError;
    decltype(&SemVpSwitchMode) SwitchMode;
    decltype(&SemVpRestoreExceptionContext) RestoreException;
    decltype(&SemVpGetCurrentTeb) GetCurrentTeb;
} SEM_PROVIDER_CALLBACKS, *PSEM_PROVIDER_CALLBACKS;

EXTERN_C
VOID
SemRegisterSystemCallProvider (
    _In_ CONST SEM_PROVIDER_CALLBACKS* SemCallbacks
);
