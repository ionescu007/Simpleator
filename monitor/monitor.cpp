/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    monitor.cpp

Abstract:

    This module handles the processing loop for Simple Emulator Pipe Messages

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "mon.h"

VOID
Trace (
    _In_ PCCH pszMessage,
    ...
    )
{
    va_list list;

    //
    // Begin var arg processing
    //
    va_start(list, pszMessage);

    //
    // Print out the message in the appropriate colors and location
    //
    printf(ESC "7" CSI "30;1H" CSI "K" CSI "44;96m");
    vprintf(pszMessage, list);
    printf(CSI "44m" ESC "8");

    //
    // Terminate var arg processing
    //
    va_end(list);
}

ULONG
SemMonThread (
    _In_ LPVOID Parameter
    )
{
    SEM_PIPE_BUFFER_MSG pipeBuffer;
    ULONG bytesRead;
    BOOL bRes;
    do
    {
        //
        // Read a message from the pipe
        //
        bRes = ReadFile(reinterpret_cast<HANDLE>(Parameter),
                        &pipeBuffer,
                        sizeof(pipeBuffer),
                        &bytesRead,
                        NULL);
        if ((bRes != FALSE) &&
            (bytesRead >= FIELD_OFFSET(SEM_PIPE_BUFFER_MSG, Data)))
        {
            if (pipeBuffer.MessageType == SemUpdateRegisters)
            {
                //
                // Send the text to the window
                //
                UpdateRegisterWindow(&pipeBuffer);
            }
            else if (pipeBuffer.MessageType == SemUpdateDebugTrace)
            {
                //
                // Send the text to the window
                //
                UpdateDebugMonitor(pipeBuffer.Data,
                                   bytesRead - 1 -
                                   FIELD_OFFSET(SEM_PIPE_BUFFER_MSG, Data));
            }
            else if (pipeBuffer.MessageType == SemInternalError)
            {
                //
                // Print out the error on the console
                //
                printf(CSI "44;91m"
                       "[VMERROR] %s"
                       ESC "(0" CSI "44;93m\tx\tx\tx" CSI "Z" CSI "Zx" ESC "(B",
                       pipeBuffer.Data);
            }
            else if (pipeBuffer.MessageType == SemSystemCall)
            {
                //
                // Add the header and then parse each argument
                //
                printf(CSI "44;97m"
                       "[SYSCALL] (%d, %s)",
                       pipeBuffer.SystemCall.Index,
                       pipeBuffer.SystemCall.Name);
                for (auto i = 0; i < pipeBuffer.SystemCall.ArgumentCount; i++)
                {
                    //
                    // Every 4 arguments add a new line to start over
                    // Then add the indented argument
                    //
                    if ((i % 4) == 0)
                    {
                        printf("\t" ESC "(0" CSI "44;93mx\tx" ESC "(B");
                    }
                    printf(CSI "44;97m"
                           "    Arg%d=0x%016I64X",
                           i,
                           pipeBuffer.SystemCall.Arguments[i]);
                }

                //
                // Add the result
                //
                printf("\t" ESC "(0" CSI "44;93mx\tx" ESC "(B" CSI "44;97m"
                       "    Ret=%08lx"
                       ESC "(0" CSI "44;93m\tx\tx\tx" CSI "Z" CSI "Zx" ESC "(B",
                       pipeBuffer.SystemCall.Result);
            }
            else
            {
                DbgRaiseAssertionFailure();
            }
        }
    } while (bRes != FALSE);
    return 0;
}

VOID
MonitorLoop (
    _In_ HANDLE MonitorThread,
    _In_ HANDLE EmulatorHandle
    )
{
    HANDLE handleArray[1];
    MSG msg;
    DWORD exitCode;
    DWORD handleCount;

    //
    // Wait on the monitor thread as well as window messages
    //
    handleArray[0] = MonitorThread;
    handleCount = _countof(handleArray);
    for (;;)
    {
        //
        // Do the wait
        //
        auto waitResult = MsgWaitForMultipleObjectsEx(handleCount,
                                                      handleArray,
                                                      INFINITE,
                                                      QS_ALLINPUT,
                                                      MWMO_ALERTABLE |
                                                      MWMO_INPUTAVAILABLE);

        //
        // If the thread is the one that died, stop waiting on it
        //
        if (waitResult == handleCount - 1)
        {
            //
            // This'll make future window messages hit the codepath below
            //
            handleCount = 0;
            GetExitCodeProcess(EmulatorHandle, &exitCode);
            Trace("Emulator has exited (err=%lx). "
                  "Investigate state and press ENTER to quit",
                  exitCode);
            (VOID) getc(stdin);
            printf(CSI "0m");
            printf(CSI "?1049h");
            break;
        }
        else if (waitResult == handleCount)
        {
            //
            // This is a window message, so pull it, handle it, and move on
            //
            if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }
}

auto
wmain (
    _In_ INT ArgumentCount,
    _In_ PWCHAR Arguments[]
    ) -> INT
{
    SECURITY_ATTRIBUTES secAttr;
    HANDLE clientPipe, serverPipe;
    LPPROC_THREAD_ATTRIBUTE_LIST attributeList;
    SIZE_T size;
    PROCESS_INFORMATION procInfo;
    STARTUPINFOEX startupInfo;
    ULONG mode;
    CONSOLE_SCREEN_BUFFER_INFOEX info;
    DWORD dwMode;

    //
    // Initialize for failure path
    //
    ZeroMemory(&procInfo, sizeof(procInfo));
    attributeList = nullptr;
    clientPipe = serverPipe = INVALID_HANDLE_VALUE;
    size = 0;

    //
    // Print usage
    //
    if (ArgumentCount != 2)
    {
        wprintf(L"Usage: simpleator <path to image>\n");
        goto Fail;
    }

    //
    // Create new console
    //
    FreeConsole();
    AllocConsole();

    //
    // Enable VT-100 processing
    //
    auto hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    //
    // Set desired screen buffer and monitor window position
    //
    MoveWindow(GetConsoleWindow(), 0, 0, 1500, 640, TRUE);
    info.cbSize = sizeof(info);
    GetConsoleScreenBufferInfoEx(hOut, &info);
    info.dwSize.X = 120;
    info.dwSize.Y = 30;
    SetConsoleScreenBufferInfoEx(hOut, &info);

    //
    // Setup initial VT-100 settings and screen buffers
    //
    printf(CSI "1;1H" CSI "44m" CSI "2J");
    printf(CSI "1;1H" CSI "102;30mSimpleator v1.1.0-BETA [%S]", Arguments[1]);
    printf(CSI "2;1H" ESC "(0" CSI "44;93ml"
           "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
           "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
           "qqqqqqqqqqqqqqqqqq"
           "k" ESC "(B");
    printf(CSI "29;1H" ESC "(0m"
           "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
           "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
           "qqqqqqqqqqqqqqqqqq"
           "j" ESC "(B");
    printf(CSI "3g" ESC "H" OSC "0;Monitor Window\x07");
    printf(CSI "3;1H" ESC "(0"
           "x\tx\tx\tx\tx\tx\tx\tx\tx\tx\tx\tx\t"
           "x\tx\tx\tx\tx\tx\tx\tx\tx\tx\tx\tx\t"
           "x\tx\tx\tx\tx\tx\tx\tx\tx\tx\tx\tx\t"
           "x\tx\tx\tx\tx\tx\tx\tx\tx\tx\tx\tx\t"
           "x\tx\tx\tx\t"
           ESC "(B");
    printf(CSI "3;28r" CSI "3;2H");

    //
    // Print monitor text
    //
    Trace("The picoVM is launching...");

    //
    // Get the size of an attribute list with one item
    //
    auto bRes = InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    if ((bRes != FALSE) || (size == 0))
    {
        Trace("Failed to get size of attribute list (err=%d)\n",
              GetLastError());
        goto Fail;
    }

    //
    // Allocate it
    //
    attributeList = reinterpret_cast<decltype(attributeList)>(
                        HeapAlloc(GetProcessHeap(), 0, size));
    if (attributeList == nullptr)
    {
        Trace("Failed to allocate attribute list (err=%d)\n",
              GetLastError());
        goto Fail;
    }

    //
    // Now initialize it
    //
    bRes = InitializeProcThreadAttributeList(attributeList, 1, 0, &size);
    if (bRes == FALSE)
    {
        Trace("Failed to initialize attribute list (err=%d)\n",
              GetLastError());
        goto Fail;
    }

    //
    // Create the server pipe
    //
    serverPipe = CreateNamedPipe(L"\\\\.\\pipe\\SimplePipe",
                                 PIPE_ACCESS_DUPLEX,
                                 PIPE_TYPE_MESSAGE |
                                 PIPE_READMODE_MESSAGE |
                                 PIPE_WAIT,
                                 1,
                                 0,
                                 0,
                                 0,
                                 NULL);
    if (serverPipe == INVALID_HANDLE_VALUE)
    {
        Trace("Failed to create named pipe (err=%d)\n",
              GetLastError());
        goto Fail;
    }

    //
    // Open the client end of the pipe and mark it inheritable
    //
    secAttr.bInheritHandle = TRUE;
    secAttr.nLength = sizeof(secAttr);
    secAttr.lpSecurityDescriptor = NULL;
    clientPipe = CreateFile(L"\\\\.\\pipe\\SimplePipe",
                            GENERIC_WRITE,
                            FILE_SHARE_WRITE | FILE_SHARE_READ,
                            &secAttr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
    if (serverPipe == INVALID_HANDLE_VALUE)
    {
        Trace("Failed to open client end of named pipe (err=%d)\n",
              GetLastError());
        goto Fail;
    }

    //
    // Set the client to message mode
    //
    mode = PIPE_READMODE_MESSAGE;
    bRes = SetNamedPipeHandleState(clientPipe, &mode, NULL, NULL);
    if (bRes == FALSE)
    {
        Trace("Failed to change pipe message state (err=%d)\n",
              GetLastError());
        goto Fail;
    }

    //
    // Add the client pipe handle to the list of inheritable handles
    //
    bRes = UpdateProcThreadAttribute(attributeList,
                                     0,
                                     PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                     &clientPipe,
                                     sizeof(clientPipe),
                                     NULL, 
                                     NULL);
    if (bRes == FALSE)
    {
        Trace("Failed to update process attribute list (err=%d)\n",
              GetLastError());
        goto Fail;
    }

    //
    // Setup the startup information to use the duplicate pipe handle as STDOUT
    //
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.lpAttributeList = attributeList;
    startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.StartupInfo.hStdOutput = clientPipe;

    //
    // Begin a loop launching the emulator
    //
    for (;;)
    {
        //
        // Start it up, passing in the target binary name
        //
        ZeroMemory(&procInfo, sizeof(procInfo));
        bRes = CreateProcess(L"emulator.exe",
                             GetCommandLine(),
                             NULL,
                             NULL,
                             TRUE,
                             CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                             NULL,
                             NULL,
                             &startupInfo.StartupInfo,
                             &procInfo);

        //
        // If we couldn't launch the process, stop trying to launch it
        //
        if (bRes == FALSE)
        {
            Trace("Failed to launch process (err=%d)\n",
                  GetLastError());
            goto Fail;
        }

        //
        // Try to reserve the bottom 2GB
        //
        auto base = VirtualAllocEx(procInfo.hProcess,
                                   s_LowestValidAddress,
                                   reinterpret_cast<ULONG_PTR>(
                                       s_UserSharedData) -
                                   reinterpret_cast<ULONG_PTR>(
                                       s_LowestValidAddress),
                                   MEM_RESERVE,
                                   PAGE_READWRITE);
        if (base == s_LowestValidAddress)
        {
            //
            // Now allocate everything from 2GB to 256GB
            //
            base = VirtualAllocEx(procInfo.hProcess,
                                  s_UserSharedDataEnd,
                                  s_256GB -
                                  reinterpret_cast<ULONG_PTR>(
                                      s_UserSharedDataEnd),
                                  MEM_RESERVE,
                                  PAGE_READWRITE);
            if (base == s_UserSharedDataEnd)
            {
                //
                // We have reserved the address space, emulator is ready to go!
                //
                break;
            }
        }

        //
        // We failed to obtain the reservation we need, try relaunching
        //
        TerminateProcess(procInfo.hProcess, GetLastError());
        CloseHandle(procInfo.hThread);
        CloseHandle(procInfo.hProcess);
    }

    //
    // Now close our copy of the duplicated pipe handle
    //
    CloseHandle(clientPipe);
    clientPipe = INVALID_HANDLE_VALUE;

    //
    // Create the debugger/monitor windows
    //
    auto hr = SemCreateDebuggerWindows();
    if (FAILED(hr))
    {
        goto Fail;
    }

    //
    // Create the pipe monitor thread
    //
    auto hThread = CreateThread(NULL,
                                0,
                                SemMonThread,
                                reinterpret_cast<PVOID>(serverPipe),
                                0,
                                NULL);
    if (hThread == nullptr)
    {
        goto Fail;
    }

    //
    // Start the emulator and close our handles to it
    //
    ResumeThread(procInfo.hThread);
    CloseHandle(procInfo.hThread);
    procInfo.hThread = nullptr;

    //
    // Print monitor text
    //
    Trace("The picoVM is executing...");

    //
    // Now we'll block until the emulator exists
    //
    MonitorLoop(hThread, procInfo.hProcess);
    CloseHandle(hThread);

Fail:
    //
    // Cleanup all our handles and allocations if any are dangling
    //
    if (procInfo.hProcess != nullptr)
    {
        CloseHandle(procInfo.hProcess);
    }
    if (procInfo.hThread != nullptr)
    {
        CloseHandle(procInfo.hThread);
    }
    if (attributeList != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, attributeList);
    }
    return 0;
}
