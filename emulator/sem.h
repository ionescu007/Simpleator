/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    sem.h

Abstract:

    This header defines the structures and functions of the Simple Emulator.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

//
// SDK Headers
//
#pragma once
#pragma warning(disable:4201)
#include <ntstatus.h>
#define WIN32_NO_STATUS
#define _NO_CRT_STDIO_INLINE
#include <windows.h>
#include <winhvplatform.h>
#include <winternl.h>
#include <psapi.h>
#include <strsafe.h>

//
// Internal header shared with all SEM components
//
#include "semdef.h"

//
// Internal header shared with the monitor
//
#include "semmsg.h"

//
// For each VP Thread, the TCB describes its state
//
typedef struct _THREAD_CONTROL_BLOCK
{
    UCHAR Stack[s_1MB]; // 1MB
    UCHAR Teb[8 * 1024]; // 8KB
    UCHAR Peb[4 * 1024]; // 4KB
    UCHAR Ppb[4 * 1024]; // 4KB
    UCHAR Reserved[48 * 1024];
    UCHAR NlsTables[256 * 1024]; // 256KB
    UCHAR ApiSetMap[128 * 1024]; // 128KB
    UCHAR InitialContext[64 * 1024]; // 64KB
} THREAD_CONTROL_BLOCK, *PTHREAD_CONTROL_BLOCK;
static_assert((sizeof(THREAD_CONTROL_BLOCK) % (64 * 1024)) == 0, "Fix TCB size");

//
// Mapping between our register indices (in SEM_VP) and the WHv platform
//
static constexpr WHV_REGISTER_NAME s_Registers[] =
{
    WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx,
    WHvX64RegisterRbx, WHvX64RegisterRsp, WHvX64RegisterRbp,
    WHvX64RegisterRsi, WHvX64RegisterRdi, WHvX64RegisterR8,
    WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
    WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14,
    WHvX64RegisterR15, WHvX64RegisterRip, WHvX64RegisterRflags,

    WHvX64RegisterEs, WHvX64RegisterCs, WHvX64RegisterSs,
    WHvX64RegisterDs, WHvX64RegisterFs, WHvX64RegisterGs,

    WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3,
    WHvX64RegisterCr4, WHvX64RegisterCr8,

    WHvX64RegisterEfer, WHvX64RegisterLstar, WHvRegisterPendingInterruption
};

//
// Represents a virtual processor
//
typedef struct _SEM_VP
{
    ULONG Index;
    struct _SEM_VP* Self;
    WHV_RUN_VP_EXIT_CONTEXT ExitContext;
    WHV_REGISTER_VALUE Registers[RTL_NUMBER_OF(s_Registers)];
} SEM_VP, *PSEM_VP;

//
// Represents a partition (Virtual Machine)
//
typedef struct _SEM_PARTITION
{
    WHV_PARTITION_HANDLE PartitionHandle;
    SEM_VP Vp[ANYSIZE_ARRAY];
} SEM_PARTITION, *PSEM_PARTITION;

FORCEINLINE
auto
SemPartitionFromVp (
    _In_ PSEM_VP Vp
)
{
    //
    // Given a VP, return the partition its associated with
    //
    return CONTAINING_RECORD(Vp, SEM_PARTITION, Vp[Vp->Index]);
}

//
// This is the Host-side TLS for each VP thread
//
typedef struct _SEM_VP_THREAD_STATE
{
    ULONG CpuIndex;
    PSEM_PARTITION Partition;
    ULONG_PTR InitialPc;
    ULONG_PTR InitialStack;
} SEM_VP_THREAD_STATE, *PSEM_VP_THREAD_STATE;

//
// Virtual Processor Functions
//
auto
SemVpExecuteProcessor (
    _In_ LPVOID Parameter
)->DWORD;

auto
SemVpSYSEXIT (
    _In_ PSEM_VP Vp,
    _In_ NTSTATUS Status
)->HRESULT;

auto
SemVpIRET (
    _In_ PSEM_VP Vp,
    _In_ NTSTATUS Status
)->HRESULT;

//
// Memory Functions
//
auto
SemAllocateGuestPrivateMemory (
    _In_ PSEM_PARTITION Partition,
    _In_ ULONG_PTR GuestVa,
    _In_ SIZE_T Size,
    _Outptr_ PVOID* HostVa
)->HRESULT;

//
// Partition Functions
//
auto
SemVmCreateAddressSpace (
    _In_ PSEM_PARTITION Partition
)->HRESULT;

auto
SemVmCreatePartition (
    _Outptr_ PSEM_PARTITION* Partition
)->HRESULT;

auto
SemVmInitializeAddressSpace (
    _In_ PSEM_PARTITION Partition,
    _In_ PWCHAR ImageFileName,
    _Out_ PULONG_PTR EntryPoint
)->HRESULT;

//
// Guest Trap Handlers
//
auto
SemHandleSystemCall (
    _In_ PSEM_VP Vp,
    _In_ BOOLEAN Interrupt
)->VOID;

auto
SemHandleDebugTrap (
    _In_ PSEM_VP Vp
)->NTSTATUS;

//
// Loader functions
//
auto
SemLdrLoadImage (
    _In_ PSEM_PARTITION Partition,
    _In_ PWCHAR ImagePath,
    _In_ ULONG_PTR ImageBase,
    _Out_opt_ PULONG_PTR ThreadThunk,
    _Out_ PULONG_PTR EntryPoint
)->HRESULT;

auto
SemLdrRelocateImage (
    __in PVOID NewBase
)->NTSTATUS;

//
// Debugging Functions
//
auto
SemVpDumpRegisters (
    _In_ PSEM_VP Vp
)->VOID;

auto
SemDbgTraceSystemCall (
    _In_ USHORT Index,
    _In_ PCHAR Name,
    _In_ PULONG_PTR Arguments,
    _In_ USHORT ArgumentCount,
    _In_ NTSTATUS Result
)->VOID;

//
// TLS reference to the VP of the host OS thread
//
extern thread_local PSEM_VP t_CurrentVp;

//
// The TCB is right below the 256GB boundary
//
static constexpr auto s_TcbRegionAddress = s_256GB - sizeof(THREAD_CONTROL_BLOCK);

//
// 1MB Stack, after the TCB
//
static constexpr auto s_StackSize = 1ULL * s_1MB;
static constexpr auto s_StackLimit = s_TcbRegionAddress + s_StackSize;
static_assert(s_StackSize == offsetof(THREAD_CONTROL_BLOCK, Teb), "Structure mismatch");

//
// Store the PML4 right below the 512GB boundary
//
static constexpr auto s_Pml4PhysicalAddress = s_512GB - s_1GB;

//
// Shortcuts to various addresses of fields in the TCB
//
static constexpr auto s_Teb = s_TcbRegionAddress + FIELD_OFFSET(THREAD_CONTROL_BLOCK, Teb);
static constexpr auto s_Peb = s_TcbRegionAddress + FIELD_OFFSET(THREAD_CONTROL_BLOCK, Peb);
static constexpr auto s_Ppb = s_TcbRegionAddress + FIELD_OFFSET(THREAD_CONTROL_BLOCK, Ppb);
static constexpr auto s_UserContext = s_TcbRegionAddress + FIELD_OFFSET(THREAD_CONTROL_BLOCK, InitialContext);

//
// Magic address to recognize a system call attempt occured
//
static constexpr auto s_SyscallTarget = s_256GB - 1;

//
// Various load addresses on the guest side
//
static constexpr auto s_NtdllBase = 0x10000000ULL;
static constexpr auto s_AppImageBase = 0x11000000ULL;

//
// Internal header shared with the provider
//
#include "semprov.h"
