/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    processor.cpp

Abstract:

    This module handles state management for the guest's Virtual Processor.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "sem.h"

thread_local PSEM_VP t_CurrentVp;

auto
SemVpInitialize (
    _In_ PSEM_VP Vp,
    _In_ ULONG_PTR EntryPoint,
    _In_ ULONG_PTR Stack,
    _In_ ULONG_PTR Param1,
    _In_ ULONG_PTR Param2
    )
{
    auto hPartition = SemPartitionFromVp(Vp)->PartitionHandle;
    auto regs = Vp->Registers;

    //
    // Create the virtual processor
    //
    auto hr = WHvCreateVirtualProcessor(hPartition, Vp->Index, 0);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Get the initial CPU state
    //
    RtlZeroMemory(regs, sizeof(Vp->Registers));
    hr = WHvGetVirtualProcessorRegisters(hPartition,
                                         Vp->Index,
                                         s_Registers,
                                         RTL_NUMBER_OF(Vp->Registers),
                                         regs);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // CS = 0x33, Ring 3, Code Segment, Long Mode
    //
    regs[WHvX64RegisterCs].Segment.DescriptorPrivilegeLevel = 3;
    regs[WHvX64RegisterCs].Segment.Long = 1;
    regs[WHvX64RegisterCs].Segment.Selector = 0x33;

    //
    // SS, DS, ES, GS = 0x2B, Ring 3, Data Segment
    //
    regs[WHvX64RegisterSs].Segment.Selector = 0x2B;
    regs[WHvX64RegisterSs].Segment.DescriptorPrivilegeLevel = 3;
    regs[WHvX64RegisterDs] = Vp->Registers[WHvX64RegisterSs];
    regs[WHvX64RegisterEs] = Vp->Registers[WHvX64RegisterSs];
    regs[WHvX64RegisterGs] = Vp->Registers[WHvX64RegisterSs];
    regs[WHvX64RegisterGs].Segment.Base = s_Teb;

    //
    // CR3 = PML4 at s_Pml4PhysicalAddress
    //
    regs[WHvX64RegisterCr3 - 4].Reg64 = s_Pml4PhysicalAddress;

    //
    // CR0 = pg, pe, mp, ...
    // CR4 = pae, ... NO SMEP
    // EFER = lma, lme, sce, ...
    //
    regs[WHvX64RegisterCr0 - 4].Reg64 = 0x80050033;
    regs[WHvX64RegisterCr4 - 4].Reg64 = 0x6E8;
    regs[29].Reg64 = 0xD01;

    // 
    // Set RSP and RIP to point to stack and entrypoint
    //
    regs[WHvX64RegisterRsp].Reg64 = Stack - 8; // For XMM Alignment
    regs[WHvX64RegisterRip].Reg64 = EntryPoint;

    //
    // Set RCX and RDX to input parameters
    //
    regs[WHvX64RegisterRcx].Reg64 = Param1;
    regs[WHvX64RegisterRdx].Reg64 = Param2;

    //
    // RFLAGS = nv up ei pl nz na pe nc
    //
    regs[WHvX64RegisterRflags].Reg64 = 0x202;

    //
    // SYSCALL CS = s_SyscallTarget
    //
    regs[30].Reg64 = s_SyscallTarget;

    //
    // Update the register state
    //
    return WHvSetVirtualProcessorRegisters(hPartition,
                                           Vp->Index,
                                           s_Registers,
                                           RTL_NUMBER_OF(Vp->Registers),
                                           regs);
}

auto
SemVpGetCurrentTeb (
    VOID
    ) -> PTEB
{
    //
    // Get the value of the GS segment in the guest, where the TEB is stored
    //
    auto gsBase = t_CurrentVp->Registers[WHvX64RegisterGs].Segment.Base;
    return reinterpret_cast<PTEB>(gsBase);
}

auto
SemVpRestoreExceptionContext (
    _In_ UINT64 Rsp,
    _In_ UINT64 Rbp,
    _In_ UINT64 Rsi,
    _In_ UINT64 Rdi,
    _In_ UINT64 Rbx,
    _In_ UINT64 Rcx
    ) -> HRESULT
{
    auto Vp = t_CurrentVp;
    auto hPartition = SemPartitionFromVp(Vp)->PartitionHandle;
    auto regs = Vp->Registers;

    //
    // Update the registers
    //
    regs[WHvX64RegisterRsp].Reg64 = Rsp;
    regs[WHvX64RegisterRbp].Reg64 = Rbp;
    regs[WHvX64RegisterRsi].Reg64 = Rsi;
    regs[WHvX64RegisterRdi].Reg64 = Rdi;
    regs[WHvX64RegisterRbx].Reg64 = Rbx;
    regs[WHvX64RegisterRcx].Reg64 = Rcx;
    return WHvSetVirtualProcessorRegisters(hPartition,
                                           Vp->Index,
                                           s_Registers,
                                           RTL_NUMBER_OF(Vp->Registers),
                                           regs);
}

auto
SemVpSwitchMode (
    _In_ UINT64 Rcx,
    _In_ UINT64 Rdx,
    _In_ UINT64 Flags,
    _In_ UINT64 StackPointer,
    _In_ UINT64 ProgramCounter,
    _In_ UINT16 CodeSeg,
    _In_ UINT16 StackSeg
    ) -> HRESULT
{
    auto Vp = t_CurrentVp;
    auto hPartition = SemPartitionFromVp(Vp)->PartitionHandle;
    auto regs = Vp->Registers;

    //
    // Update the registers
    // Note that WHV enforces having flag 0x2 set in EFLAGS
    //
    regs[WHvX64RegisterRcx].Reg64 = Rcx;
    regs[WHvX64RegisterRdx].Reg64 = Rdx;
    regs[WHvX64RegisterRflags].Reg64 = Flags | 2;
    regs[WHvX64RegisterRsp].Reg64 = StackPointer;
    regs[WHvX64RegisterRip].Reg64 = ProgramCounter;
    regs[WHvX64RegisterCs].Segment.Selector = CodeSeg;
    regs[WHvX64RegisterCs].Segment.DescriptorPrivilegeLevel = 3;
    regs[WHvX64RegisterSs].Segment.Selector = StackSeg;
    regs[WHvX64RegisterSs].Segment.DescriptorPrivilegeLevel = 3;
    regs[31].PendingInterruption.AsUINT64 = 0;
    return WHvSetVirtualProcessorRegisters(hPartition,
                                           Vp->Index,
                                           s_Registers,
                                           RTL_NUMBER_OF(Vp->Registers),
                                           regs);
}

auto
SemVpSYSEXIT (
    _In_ PSEM_VP Vp,
    _In_ NTSTATUS Status
    ) -> HRESULT
{
    auto hPartition = SemPartitionFromVp(Vp)->PartitionHandle;
    auto regs = Vp->Registers;

    //
    // Set RAX to the result
    //
    regs[WHvX64RegisterRax].Reg64 = Status;

    //
    // Restore RFLAGS and RIP just like SYSEXIT would
    //
    regs[WHvX64RegisterRflags] = regs[WHvX64RegisterR11];
    regs[WHvX64RegisterRip] = regs[WHvX64RegisterRcx];

    //
    // Restore CS to Ring 3 Selector 33h and SS to Ring 3 Selector 2Bh
    //
    regs[WHvX64RegisterCs].Segment.DescriptorPrivilegeLevel = 3;
    regs[WHvX64RegisterCs].Segment.Selector = 0x33;
    regs[WHvX64RegisterSs].Segment.DescriptorPrivilegeLevel = 3;
    regs[WHvX64RegisterSs].Segment.Selector = 0x2B;

    //
    // Update the registers
    //
    return WHvSetVirtualProcessorRegisters(hPartition,
                                           Vp->Index,
                                           s_Registers,
                                           RTL_NUMBER_OF(Vp->Registers),
                                           regs);
}

auto
SemVpIRET (
    _In_ PSEM_VP Vp,
    _In_ NTSTATUS Status
    ) -> HRESULT
{
    auto hPartition = SemPartitionFromVp(Vp)->PartitionHandle;
    auto regs = Vp->Registers;

    //
    // Set RAX to the result, skip past the instruction, and acquiesce
    //
    regs[WHvX64RegisterRax].Reg64 = Status;
    regs[WHvX64RegisterRip].Reg64 += regs[31].PendingInterruption.InstructionLength;
    regs[31].PendingInterruption.AsUINT64 = 0;

    //
    // Update the registers
    //
    return WHvSetVirtualProcessorRegisters(hPartition,
                                           Vp->Index,
                                           s_Registers,
                                           RTL_NUMBER_OF(Vp->Registers),
                                           regs);
}

auto
SemVpINT (
    _In_ PSEM_VP Vp
    )
{
    //
    // Check which interrupt vector this was
    //
    auto vector = Vp->Registers[31].PendingInterruption.InterruptionVector;
    if (vector == 0x2D)
    {
        //
        // Handle DEBUG_BREAKPOINT Trap
        //
        SemVpIRET(Vp, SemHandleDebugTrap(Vp));
    }
    else if (vector == 0x2E)
    {
        //
        // Handle System Call Trap (with HVCI)
        //
        SemHandleSystemCall(Vp, TRUE);
    }
    else
    {
        //
        // Generic unhandled software interrupt
        //
        DbgRaiseAssertionFailure();
        SemVpIRET(Vp, STATUS_ASSERTION_FAILURE);
    }
}

auto
SemVpHandleMemoryAccessExit (
    _In_ PSEM_VP Vp
    )
{
    //
    // Check if this is a memory access on the special SYSCALL RIP
    //
    if (Vp->ExitContext.MemoryAccess.Gpa == s_SyscallTarget)
    {
        //
        // Go handle a system call
        //
        SemHandleSystemCall(Vp, FALSE);
    }
    else if (Vp->ExitContext.VpContext.ExecutionState.InterruptionPending != FALSE)
    {
        //
        // We don't have an IDT, so interrupts will look like invalid memory accesses
        //
        SemVpINT(Vp);
    }
    else
    {
        //
        // Print out a fault for debugging
        //
        DbgRaiseAssertionFailure();
    }
}

auto
SemVpRun (
    _In_ PSEM_VP Vp,
    _Out_ WHV_RUN_VP_EXIT_REASON* ExitReason
    )
{
    auto hPartition = SemPartitionFromVp(Vp)->PartitionHandle;

    //
    // Run the guest
    //
    auto hr = WHvRunVirtualProcessor(hPartition,
                                     Vp->Index,
                                     &Vp->ExitContext,
                                     sizeof(Vp->ExitContext));
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Return why we exited
    //
    *ExitReason = Vp->ExitContext.ExitReason;

    //
    // Get the current CPU state
    //
    return WHvGetVirtualProcessorRegisters(hPartition,
                                           Vp->Index,
                                           s_Registers,
                                           RTL_NUMBER_OF(Vp->Registers),
                                           Vp->Registers);
}

auto
SemVpExecuteProcessor (
    _In_ LPVOID Parameter
    ) -> DWORD
{
    auto threadState = static_cast<PSEM_VP_THREAD_STATE>(Parameter);
    WHV_RUN_VP_EXIT_REASON exitReason;

    //
    // Get the partition and VP that we are emulating on this thread
    //
    auto partition = threadState->Partition;
    auto vp = &partition->Vp[threadState->CpuIndex];

    //
    // Initialize the virtual processor state for this thread
    //
    vp->Index = threadState->CpuIndex;
    vp->Self = vp;
    t_CurrentVp = vp;

    //
    // Initialize the initial processor state (registers)
    //
    auto hr = SemVpInitialize(vp,
                              threadState->InitialPc,
                              threadState->InitialStack,
                              s_UserContext,
                              s_NtdllBase);
    if (FAILED(hr))
    {
        SemVmError("Processor initialization failed: %lx\n", hr);
        goto Exit;
    }

    //
    // This is the main guest VM execution loop
    //
    for (;;)
    {
        //
        // Execute processor run loop
        //
        hr = SemVpRun(vp, &exitReason);
        if (FAILED(hr))
        {
            SemVmError("Processor execution failed: %lx\n", hr);
            break;
        }

        //
        // The VP returned due to an exit -- handle each case
        // Update the register window on each exit
        //
        SemVpDumpRegisters(vp);
        if (exitReason == WHvRunVpExitReasonMemoryAccess)
        {
            //
            // Invalid memory access, which could be a system call
            //
            SemVpHandleMemoryAccessExit(vp);
        }
        else
        {
            //
            // Something we don't handle (yet)
            //
            SemVmError("Unhandled exit reason: %lx\n", exitReason);
            DbgRaiseAssertionFailure();
            break;
        }
    }
Exit:
    return 0;
}
