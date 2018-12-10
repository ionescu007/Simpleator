/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    debug.cpp

Abstract:

    This module implements the debugging pipe for talking with the monitor

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "sem.h"

auto
SemDbgTraceSystemCall (
    _In_ USHORT Index,
    _In_ PCHAR Name,
    _In_ PULONG_PTR Arguments,
    _In_ USHORT ArgumentCount,
    _In_ NTSTATUS Result
    ) -> VOID
{
    SEM_PIPE_BUFFER_MSG msg;

    //
    // Build the payload
    //
    msg.MessageType = SemSystemCall;
    msg.SystemCall.ArgumentCount = ArgumentCount;
    msg.SystemCall.Index = Index;
    memcpy(msg.SystemCall.Name, Name, strlen(Name) + 1);
    for (auto i = 0UL; i < ArgumentCount; i++)
    {
        msg.SystemCall.Arguments[i] = Arguments[i];
    }
    msg.SystemCall.Result = Result;

    //
    // Send it to the monitor
    //
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &msg, sizeof(msg), NULL, NULL);
}

auto
SemVpDumpRegisters (
    _In_ PSEM_VP Vp
    ) -> VOID
{
    SEM_PIPE_BUFFER_MSG msg;
    auto regs = Vp->Registers;

    //
    // Build the payload and send it to the monitor
    //
    msg.MessageType = SemUpdateRegisters;
    memcpy(&msg.Registers, regs, sizeof(msg.Registers));
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &msg, sizeof(msg), NULL, NULL);
};

auto
SemVmError (
    _In_ PCHAR ErrorString,
    ...
    ) -> VOID
{
    SEM_PIPE_BUFFER_MSG pipeMessage;
    PCHAR endString;
    va_list argList;
    va_start(argList, ErrorString);

    //
    // Build the payload and send it to the monitor
    //
    pipeMessage.MessageType = SemInternalError;
    StringCbVPrintfExA(pipeMessage.Data,
                       sizeof(pipeMessage.Data),
                       &endString,
                       NULL,
                       0,
                       ErrorString,
                       argList);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
              &pipeMessage,
              static_cast<DWORD>(
                  endString + 1 - reinterpret_cast<PCHAR>(&pipeMessage)),
              NULL,
              NULL);
    va_end(argList);
}

auto
SemVmDebugPrint (
    _In_ PCHAR Buffer,
    _In_ ULONG Length
    ) -> VOID
{
    SEM_PIPE_BUFFER_MSG msg;

    //
    // Build the payload and send it to the monitor
    //
    msg.MessageType = SemUpdateDebugTrace;
    memcpy(msg.Data, Buffer, Length);
    msg.Data[Length] = ANSI_NULL;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
              &msg,
              FIELD_OFFSET(SEM_PIPE_BUFFER_MSG, Data) + Length,
              NULL,
              NULL);
}
