/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    emulator.cpp

Abstract:

    This module implements the main Simple Emulator initialization code.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "sem.h"

const static SEM_PROVIDER_CALLBACKS s_SemCallbacks =
{
    IsGuestMemoryPtr,
    SemMmMapSharedImage,
    SemMmMapSharedMemory,
    SemMmUnmapSharedMemory,
    SemRegisterSystemCall,
    SemRegisterDebugTrap,
    SemVmDebugPrint,
    SemVmError,
    SemVpSwitchMode,
    SemVpRestoreExceptionContext,
    SemVpGetCurrentTeb
};

auto
SemMain (
    VOID
    )
{
    ULONG_PTR entryPoint;
    PSEM_PARTITION semPartition;
    SEM_VP_THREAD_STATE threadState;
    UINT32 bytesWritten;
    WHV_CAPABILITY whvCapability;
    auto dwExitCode = -1;

    //
    // First, check if the feature is enabled
    //
    auto hr = WHvGetCapability(WHvCapabilityCodeHypervisorPresent,
                               &whvCapability,
                               sizeof(whvCapability),
                               &bytesWritten);
    if (FAILED(hr) || (whvCapability.HypervisorPresent == FALSE))
    {
        SemVmError("Windows Hypervisor Platform is not enabled: %lx\n", hr);
        goto Cleanup;
    }

    //
    // Next, check for partial unmapping support
    //
    hr = WHvGetCapability(WHvCapabilityCodeFeatures,
                          &whvCapability,
                          sizeof(whvCapability),
                          &bytesWritten);
    if (FAILED(hr) || (whvCapability.Features.PartialUnmap == FALSE))
    {
        SemVmError("Windows Hypervisor Platform is not enabled: %lx\n", hr);
        goto Cleanup;
    }

    //
    // Extended Vid is active, create the hypervisor partition
    //
    hr = SemVmCreatePartition(&semPartition);
    if (FAILED(hr))
    {
        SemVmError("Partition creation failed: %lx\n", hr);
        goto Cleanup;
    }

    //
    // Loader should've created a 256GB region for us, we can now free it
    //
    auto bRes = VirtualFreeEx(GetCurrentProcess(),
                              s_LowestValidAddress,
                              0,
                              MEM_RELEASE);
    if (bRes != FALSE)
    {
        bRes = VirtualFreeEx(GetCurrentProcess(),
                             s_UserSharedDataEnd,
                             0,
                             MEM_RELEASE);
    }
    if ((bRes == FALSE) && (IsDebuggerPresent() == FALSE))
    {
        SemVmError("256GB Reservation not found -- "
                   "please do not launch this binary directly\n");
        goto Cleanup;
    }

    //
    // Create the address space of the guest
    //
    hr = SemVmCreateAddressSpace(semPartition);
    if (FAILED(hr))
    {
        SemVmError("Address space creation failed: %lx\n", hr);
        goto Cleanup;
    }

    //
    // Initialize the address space for the target image
    //
    hr = SemVmInitializeAddressSpace(semPartition,
                                     wcschr(GetCommandLine(), L' ') + 2,
                                     &entryPoint);
    if (FAILED(hr))
    {
        SemVmError("Address space initialization failed: %lx\n", hr);
        goto Cleanup;
    }

    //
    // Register system call support
    //
    SemRegisterSystemCallProvider(&s_SemCallbacks);

    //
    // Run the processor thread
    //
    threadState.CpuIndex = 0;
    threadState.Partition = semPartition;
    threadState.InitialPc = entryPoint;
    threadState.InitialStack = s_StackLimit;
    auto hThread = CreateThread(NULL,
                                0,
                                SemVpExecuteProcessor,
                                &threadState,
                                0,
                                NULL);
    if (hThread == nullptr)
    {
        SemVmError("Emulator thread creation failed: %lx\n", GetLastError());
        goto Cleanup;
    }

    //
    // When the thread dies, we exit too
    //
    WaitForSingleObject(hThread, INFINITE);
    dwExitCode = 0;

Cleanup:
    return dwExitCode;
}
