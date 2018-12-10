/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    syscalls.cpp

Abstract:

    This module implements handling Ring 3->0 transitions from the guest VM.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "sem.h"

//
// Support for system call emulation for up to 11 arguments
//
#define MAX_SYSTEM_CALL_INDEX   500
typedef SEM_SYSCALL_STATUS (*PNT_NO_ARGUMENTS) (VOID);
typedef SEM_SYSCALL_STATUS (*PNT_ONE_ARGUMENT) (ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_TWO_ARGUMENTS) (ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_THREE_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_FOUR_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_FIVE_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_SIX_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_SEVEN_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_EIGHT_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_NINE_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_TEN_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef SEM_SYSCALL_STATUS (*PNT_ELEVEN_ARGUMENTS) (ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef struct _SEM_SYSTEM_CALL_DESCRIPTOR
{
    UCHAR Arguments;
    PVOID Handler;
    PCHAR Name;
} SEM_SYSTEM_CALL_DESCRIPTOR, *PSEM_SYSTEM_CALL_DESCRIPTOR;
static SEM_SYSTEM_CALL_DESCRIPTOR s_SystemCalls[MAX_SYSTEM_CALL_INDEX];

typedef struct _SEM_DEBUG_TRAP_DESCRIPTOR
{
    UCHAR Arguments;
    PVOID Handler;
} SEM_DEBUG_TRAP_DESCRIPTOR, *PSEM_DEBUG_TRAP_DESCRIPTOR;
#define MAX_DEBUG_TRAP          5
static SEM_DEBUG_TRAP_DESCRIPTOR s_DebugTraps[MAX_DEBUG_TRAP];

//
// Generic Handler for N-arguments
//
typedef
auto
(SEM_HANDLE_SYSCALL) (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS;
typedef SEM_HANDLE_SYSCALL* PSEM_HANDLE_SYSCALL;

auto
SemHandleSystemCall11 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 9-argument handler
    //
    return ((PNT_ELEVEN_ARGUMENTS)Handler)(Arguments[0],
                                           Arguments[1],
                                           Arguments[2],
                                           Arguments[3],
                                           Arguments[4],
                                           Arguments[5],
                                           Arguments[6],
                                           Arguments[7],
                                           Arguments[8],
                                           Arguments[9],
                                           Arguments[10]);
}

auto
SemHandleSystemCall10 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 9-argument handler
    //
    return ((PNT_TEN_ARGUMENTS)Handler)(Arguments[0],
                                        Arguments[1],
                                        Arguments[2],
                                        Arguments[3],
                                        Arguments[4],
                                        Arguments[5],
                                        Arguments[6],
                                        Arguments[7],
                                        Arguments[8],
                                        Arguments[9]);
}

auto
SemHandleSystemCall9 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 9-argument handler
    //
    return ((PNT_NINE_ARGUMENTS)Handler)(Arguments[0],
                                         Arguments[1],
                                         Arguments[2],
                                         Arguments[3],
                                         Arguments[4],
                                         Arguments[5],
                                         Arguments[6],
                                         Arguments[7],
                                         Arguments[8]);
}

auto
SemHandleSystemCall8 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 8-argument handler
    //
    return ((PNT_EIGHT_ARGUMENTS)Handler)(Arguments[0],
                                          Arguments[1],
                                          Arguments[2],
                                          Arguments[3],
                                          Arguments[4],
                                          Arguments[5],
                                          Arguments[6],
                                          Arguments[7]);
}

auto
SemHandleSystemCall7 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 7-argument handler
    //
    return ((PNT_SEVEN_ARGUMENTS)Handler)(Arguments[0],
                                          Arguments[1],
                                          Arguments[2],
                                          Arguments[3],
                                          Arguments[4],
                                          Arguments[5],
                                          Arguments[6]);
}

auto
SemHandleSystemCall6 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 6-argument handler
    //
    return ((PNT_SIX_ARGUMENTS)Handler)(Arguments[0],
                                        Arguments[1],
                                        Arguments[2],
                                        Arguments[3],
                                        Arguments[4],
                                        Arguments[5]);
}

auto
SemHandleSystemCall5 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 5-argument handler
    //
    return ((PNT_FIVE_ARGUMENTS)Handler)(Arguments[0],
                                         Arguments[1],
                                         Arguments[2],
                                         Arguments[3],
                                         Arguments[4]);
}

auto
SemHandleSystemCall4 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 4-argument handler
    //
    return ((PNT_FOUR_ARGUMENTS)Handler)(Arguments[0],
                                         Arguments[1],
                                         Arguments[2],
                                         Arguments[3]);
}

auto
SemHandleSystemCall3 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 3-argument handler
    //
    return ((PNT_THREE_ARGUMENTS)Handler)(Arguments[0],
                                          Arguments[1],
                                          Arguments[2]);
}

auto
SemHandleSystemCall2 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 2-argument handler
    //
    return ((PNT_TWO_ARGUMENTS)Handler)(Arguments[0],
                                        Arguments[1]);
}

auto
SemHandleSystemCall1 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 1-argument handler
    //
    return ((PNT_ONE_ARGUMENT)Handler)(Arguments[0]);
}

auto
SemHandleSystemCall0 (
    _In_ PVOID Handler,
    _In_ PULONG_PTR Arguments
    ) -> SEM_SYSCALL_STATUS
{
    //
    // Call the 1-argument handler
    //
    UNREFERENCED_PARAMETER(Arguments);
    return ((PNT_NO_ARGUMENTS)Handler)();
}

static const PSEM_HANDLE_SYSCALL s_SystemCallArgHandlers[12] =
{
    SemHandleSystemCall0,
    SemHandleSystemCall1,
    SemHandleSystemCall2,
    SemHandleSystemCall3,
    SemHandleSystemCall4,
    SemHandleSystemCall5,
    SemHandleSystemCall6,
    SemHandleSystemCall7,
    SemHandleSystemCall8,
    SemHandleSystemCall9,
    SemHandleSystemCall10,
    SemHandleSystemCall11,
};

auto
SemRegisterSystemCall (
    _In_ USHORT Index,
    _In_ UCHAR Arguments,
    _In_opt_ PVOID Function,
    _In_ PCHAR FunctionName
    ) -> void
{
    //
    // This is a special way of saying the handler is a generic one which
    // return STATUS_NOT_IMPLEMENTED
    //
    if (Function == nullptr)
    {
        Function = reinterpret_cast<PVOID>(1);
    }

    //
    // Register the system call in the table
    //
    s_SystemCalls[Index].Arguments = Arguments;
    s_SystemCalls[Index].Handler = Function;
    s_SystemCalls[Index].Name = FunctionName;
}

auto
SemRegisterDebugTrap (
    _In_ USHORT Index,
    _In_ UCHAR Arguments,
    _In_ PVOID Function
    ) -> void
{
    //
    // Register the system call in the table
    //
    s_DebugTraps[Index].Arguments = Arguments;
    s_DebugTraps[Index].Handler = Function;
}

auto
IsGuestMemoryPtr (
    _In_ PVOID Address
    ) -> bool
{
    //
    // Guest memory should be between 0x10000 and 0x4000000000
    //
    if ((Address < s_LowestValidAddress) || (Address > s_HighestValidAddress))
    {
        return false;
    }
    else
    {
        //
        // And should not be in the shared memory area hole
        //
        return ((Address < s_UserSharedData) || (Address > s_UserSharedDataEnd));
    }
}

auto
SemExtractSystemCallArguments (
    _In_ PSEM_VP Vp,
    _In_ BOOLEAN Interrupt,
    _Out_ PUSHORT Index,
    _Out_ PULONG_PTR Arguments,
    _Out_ PUSHORT ArgumentCount,
    _Out_ PVOID* Handler
    )
{
    auto regs = Vp->Registers;

    //
    // Get the stack pointer at the time the system call was made and make sure
    // its valid guest memory. An even better check would be to see if it's in
    // the stack region.
    //
    auto stack = reinterpret_cast<PULONG_PTR>(regs[WHvX64RegisterRsp].Reg64);
    if (!IsGuestMemoryPtr(stack))
    {
        SemVmError("System call stack (0x%p) is invalid", stack);
        DbgRaiseAssertionFailure();
        return STATUS_INVALID_ADDRESS;
    }

    //
    // Read the system call ID and make sure it's potentially valid
    //
    *Index = regs[WHvX64RegisterRax].Reg16;
    if (*Index > _countof(s_SystemCalls))
    {
        SemVmError("System call index %d is above max supported", *Index);
        DbgRaiseAssertionFailure();
        return STATUS_IMPLEMENTATION_LIMIT;
    }

    //
    // Check if we support this system call
    //
    *Handler = s_SystemCalls[*Index].Handler;
    if (*Handler == nullptr)
    {
        SemVmError("System call index %d is not emulated", *Index);
        DbgRaiseAssertionFailure();
        return STATUS_NOT_IMPLEMENTED;
    }

    //
    // Go over each argument this function takes
    //
    *ArgumentCount = s_SystemCalls[*Index].Arguments;
    for (auto i = 0UL; i < *ArgumentCount; i++)
    {
        //
        // Read the first four arguments from the appropriate register
        //
        if (i == 0)
        {
            if (Interrupt != FALSE)
            {
                Arguments[i] = regs[WHvX64RegisterRcx].Reg64;
            }
            else
            {
                Arguments[i] = regs[WHvX64RegisterR10].Reg64;
            }
        }
        else if (i == 1)
        {
            Arguments[i] = regs[WHvX64RegisterRdx].Reg64;
        }
        else if (i == 2)
        {
            Arguments[i] = regs[WHvX64RegisterR8].Reg64;
        }
        else if (i == 3)
        {
            Arguments[i] = regs[WHvX64RegisterR9].Reg64;
        }
        else
        {
            //
            // Other arguments come from the stack, after home space
            // Stack pointer could be bogus, so use SEH to detect garbage
            // Note that we'll still crash, but it'll be an assertion with a
            // debugging aid to identify the situation.
            //
            _try
            {
                Arguments[i] = stack[i + 1];
            }
            _except (EXCEPTION_EXECUTE_HANDLER)
            {
                SemVmError("System call issued with bogus stack: %p",
                           &stack[i + 1]);
                DbgRaiseAssertionFailure();
                return STATUS_ACCESS_VIOLATION;
            }
        }
    }
    return STATUS_SUCCESS;
}

auto
SemHandleSystemCall (
    _In_ PSEM_VP Vp,
    _In_ BOOLEAN Interrupt
    ) -> VOID
{
    USHORT index;
    ULONG_PTR arguments[19];
    USHORT argumentCount;
    PVOID handler;
    SEM_SYSCALL_STATUS result;

    //
    // Extract the system call index and arguments, assert if anything failed
    //
    auto status = SemExtractSystemCallArguments(Vp,
                                                Interrupt,
                                                &index,
                                                arguments,
                                                &argumentCount,
                                                &handler);
    if (!NT_SUCCESS(status))
    {
        DbgRaiseAssertionFailure();
    }

    //
    // Check if this is the special value which marks this as a system call
    // which does not require implementation, otherwise go and call the wrapper
    // 
    //
    if (handler != reinterpret_cast<PVOID>(1))
    {
        result = s_SystemCallArgHandlers[argumentCount](handler, arguments);
    }
    else
    {
        result = EncodeFailureOk(STATUS_NOT_IMPLEMENTED);
    }

    //
    // Trace the result back
    //
    SemDbgTraceSystemCall(index,
                          s_SystemCalls[index].Name,
                          arguments,
                          argumentCount,
                          result.Status);

    //
    // If the system call emulation failed unexpectedly, assert
    //
    if (!(NT_SUCCESS(result.Status)) && !(result.Flags & SemFailureIsExpected))
    {
        SemVmError("System call returned unexpected error: %lx", result.Status);
        DbgRaiseAssertionFailure();
    }

    //
    // Resume after system call completion, except for special-case system
    // calls which restore CPU state differently.
    //
    if (!(result.Flags & SemDoNotResume))
    {
        if (Interrupt != FALSE)
        {
            SemVpIRET(Vp, result.Status);
        }
        else
        {
            SemVpSYSEXIT(Vp, result.Status);
        }
    }
}

auto
SemExtractDebugTrapArguments (
    _In_ PSEM_VP Vp,
    _Out_ PUSHORT Index,
    _Out_ PULONG_PTR Arguments,
    _Out_ PULONG ArgumentCount,
    _Out_ PVOID* Handler
    )
{
    auto regs = Vp->Registers;

    //
    // Get the debug trap index and make sure it's not bogus
    //
    *Index = regs[WHvX64RegisterRax].Reg16;
    if (*Index > _countof(s_DebugTraps))
    {
        SemVmError("Debug trap index %d is above max supported", *Index);
        DbgRaiseAssertionFailure();
        return STATUS_IMPLEMENTATION_LIMIT;
    }

    //
    // Debug traps always have four parameters
    //
    *ArgumentCount = s_DebugTraps[*Index].Arguments;

    //
    // Check if we support this system call
    //
    *Handler = s_DebugTraps[*Index].Handler;
    if (*Handler == nullptr)
    {
        SemVmError("Debug trap index %d is not emulated", *Index);
        DbgRaiseAssertionFailure();
        return STATUS_NOT_IMPLEMENTED;
    }

    //
    // Always capture 4 arguments since that's how much the trap always sends
    //
    Arguments[0] = regs[WHvX64RegisterRcx].Reg64;
    Arguments[1] = regs[WHvX64RegisterRdx].Reg32;
    Arguments[2] = regs[WHvX64RegisterR8].Reg32;
    Arguments[3] = regs[WHvX64RegisterR9].Reg32;
    return STATUS_SUCCESS;
}

auto
SemHandleDebugTrap (
    _In_ PSEM_VP Vp
    ) -> NTSTATUS
{
    USHORT index;
    ULONG_PTR arguments[4];
    ULONG argumentCount;
    PVOID handler;

    //
    // Extract the debug service index and arguments
    //
    auto status = SemExtractDebugTrapArguments(Vp,
                                               &index,
                                               arguments,
                                               &argumentCount,
                                               &handler);
    if (!NT_SUCCESS(status))
    {
        DbgRaiseAssertionFailure();
    }

    //
    // Call the appropriate handler for each number of arguments possible
    //
    auto result = s_SystemCallArgHandlers[argumentCount](handler, arguments);
    if (!(NT_SUCCESS(result.Status)) && !(result.Flags & SemFailureIsExpected))
    {
        DbgRaiseAssertionFailure();
    }

    //
    // Windows places an INT3 to detect correct trap handling of INT2D
    //
    Vp->Registers[WHvX64RegisterRip].Reg64 += 1;
    return result.Status;
}
