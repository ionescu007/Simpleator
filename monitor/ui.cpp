/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    ui.cpp

Abstract:

    This module implements the main UI for the Simple Emulator Debug Monitor

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "mon.h"

HWND hwndRegisterWindow;
HDC dcRegisterWindow;
RECT rcRegisterWindow;

HWND hwndDebugWindow;
HDC dcDebugWindow;
RECT rcDebugWindow;

HFONT hFont;
HBRUSH hBrush;

auto
UpdateDebugMonitor (
    _In_ PCHAR DebugMessage,
    _In_ ULONG DebugMessageLength
    ) -> VOID
{
    RECT rcClear;

    //
    // First, calculate the rectangle for this text
    //
    auto calcRes = DrawTextA(dcDebugWindow,
                             DebugMessage,
                             DebugMessageLength,
                             &rcDebugWindow,
                             DT_CALCRECT);
    if (calcRes == 0)
    {
        DbgRaiseAssertionFailure();
    }

    //
    // Clear the line we're about to draw on
    //
    rcClear = rcDebugWindow;
    rcClear.right = DEBUG_MONITOR_WINDOW_WIDTH;
    FillRect(dcDebugWindow, &rcClear, hBrush);

    //
    // Now draw the actual text, and return the height
    //
    auto height = DrawTextA(dcDebugWindow,
                            DebugMessage,
                            DebugMessageLength,
                            &rcDebugWindow,
                            DT_EXPANDTABS | DT_WORDBREAK);

    //
    // Redraw the window
    //
    RedrawWindow(hwndDebugWindow, &rcDebugWindow, NULL, RDW_UPDATENOW);

    //
    // Update the rectangle with the height of the text we just drew
    //
    OffsetRect(&rcDebugWindow, 0, height);

    //
    // If we went past the height of the window, restart at the top
    //
    if (rcDebugWindow.top > DEBUG_MONITOR_WINDOW_HEIGHT)
    {
        GetClientRect(hwndDebugWindow, &rcDebugWindow);
    }
}

auto
UpdateRegisterWindow (
    _In_ PSEM_PIPE_BUFFER_MSG Msg
    ) -> VOID
{
    CHAR regBuffer[8192];
    PCHAR buffer = regBuffer;

    //
    // Dump GPRs
    //
    buffer[0] = ANSI_NULL;
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "RAX=%016I64x RBX=%016I64x RCX=%016I64x\n",
                      Msg->Registers.Rax.LowPart,
                      Msg->Registers.Rbx.LowPart,
                      Msg->Registers.Rcx.LowPart);
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "RDX=%016I64x RSI=%016I64x RDI=%016I64x\n",
                      Msg->Registers.Rdx.LowPart,
                      Msg->Registers.Rsi.LowPart,
                      Msg->Registers.Rdi.LowPart);
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "RIP=%016I64x RSP=%016I64x RBP=%016I64x\n",
                      Msg->Registers.Rip.LowPart,
                      Msg->Registers.Rsp.LowPart,
                      Msg->Registers.Rbp.LowPart);
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      " R8=%016I64x  R9=%016I64x R10=%016I64x\n",
                      Msg->Registers.R8.LowPart,
                      Msg->Registers.R9.LowPart,
                      Msg->Registers.R10.LowPart);
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "R11=%016I64x R12=%016I64x R13=%016I64x\n",
                      Msg->Registers.R11.LowPart,
                      Msg->Registers.R12.LowPart,
                      Msg->Registers.R13.LowPart);
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "R14=%016I64x R15=%016I64x\n",
                      Msg->Registers.R14.LowPart,
                      Msg->Registers.R15.LowPart);

    //
    // Dump flags and segments
    //
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "IOPL=%01d\n",
                      (Msg->Registers.Rflags.LowPart & 0x3000) >> 12);
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "CS=%04x  SS=%04x  DS=%04x  ES=%04x  FS=%04x  GS=%04x"
                      "             EFL=%08I32x\n",
                      Msg->Registers.Cs.LowPart & 0xFFFF,
                      Msg->Registers.Ss.LowPart & 0xFFFF,
                      Msg->Registers.Ds.LowPart & 0xFFFF,
                      Msg->Registers.Es.LowPart & 0xFFFF,
                      Msg->Registers.Fs.LowPart & 0xFFFF,
                      Msg->Registers.Gs.LowPart & 0xFFFF,
                      Msg->Registers.Rflags.LowPart);

    //
    // Dump control regs
    //
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "CR0=%08I32x CR2=%016I64x CR3=%016I64x\n",
                      Msg->Registers.Cr0.LowPart,
                      Msg->Registers.Cr2.LowPart,
                      Msg->Registers.Cr3.LowPart);
    StringCbPrintfExA(buffer, sizeof(regBuffer), &buffer, NULL, 0,
                      "CR4=%08I32x CR8=%08I32x\n",
                      Msg->Registers.Cr4.LowPart,
                      Msg->Registers.Cr8.LowPart);

    //
    // Draw the text
    //
    auto height = DrawTextA(dcRegisterWindow,
                            regBuffer,
                            static_cast<DWORD>(buffer - regBuffer),
                            &rcRegisterWindow,
                            0);
    if (height == 0)
    {
        DbgRaiseAssertionFailure();
    }

    //
    // Redraw the window
    //
    RedrawWindow(hwndRegisterWindow, &rcRegisterWindow, NULL, RDW_UPDATENOW);
}

auto
CALLBACK
WindowProc (
    _In_ HWND hwnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    ) -> LRESULT
{
    PAINTSTRUCT ps;

    //
    // What window message is this?
    //
    switch (uMsg)
    {
    //
    // Paint window
    //
    case WM_PAINT:
    {
        {
            //
            // Start the paint operation
            //
            auto hdc = BeginPaint(hwnd, &ps);

            //
            // Which window is being painted?
            //
            if (hwnd == hwndDebugWindow)
            {
                //
                // The debug window has a blue background
                //
                FillRect(hdc, &ps.rcPaint, hBrush);
            }
            else
            {
                //
                // The regiser window has the default window text color
                //
                FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOWTEXT));
            }

            //
            // Finish painting
            //
            EndPaint(hwnd, &ps);
        }

        //
        // We're done here, don't let Windows paint on top
        //
        return 0;
    }

    //
    // Destroy message
    //
    case WM_DESTROY:
        //
        // Exit the message loop
        //
        PostQuitMessage(0);
        return 0;
    }

    //
    // Call the default window procedure for anything else
    //
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

auto
SemCreateDebuggerWindows (
    VOID
    ) -> HRESULT
{
    WNDCLASS wc;

    //
    // Register the window class
    //
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WindowProc;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = L"Simpleator";
    auto atomClass = RegisterClass(&wc);
    if (atomClass == FALSE)
    {
        return GetLastError();
    }

    //
    // Create a blue color brush
    //
    auto bClassRegistered = true;
    hBrush = CreateSolidBrush(RGB(0, 0, 128));
    if (hBrush == nullptr)
    {
        goto Failure;
    }

    //
    // Create the debug window
    //
    hwndDebugWindow = CreateWindowEx(0,
                                     L"Simpleator",
                                     L"Debug Output Window",
                                     WS_VISIBLE,
                                     0,
                                     DEBUG_MONITOR_WINDOW_TOP,
                                     DEBUG_MONITOR_WINDOW_WIDTH,
                                     DEBUG_MONITOR_WINDOW_HEIGHT,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL);
    if (hwndDebugWindow == nullptr)
    {
        goto Failure;
    }

    //
    // Get the display context of the debug window
    //
    dcDebugWindow = GetDC(hwndDebugWindow);
    if (dcDebugWindow == nullptr)
    {
        goto Failure;
    }

    //
    // Get the window position of the debug window
    //
    auto bRes = GetClientRect(hwndDebugWindow, &rcDebugWindow);
    if (bRes == FALSE)
    {
        goto Failure;
    }

    //
    // Fully opaque background, deep blue background, white foreground
    //
    SetBkMode(dcDebugWindow, OPAQUE);
    SetBkColor(dcDebugWindow, RGB(0, 0, 128));
    SetTextColor(dcDebugWindow, RGB(255, 255, 255));


    //
    // Use the Consolas font for this window
    //
    hFont = CreateFont(12,
                       0,
                       0,
                       0,
                       FW_HEAVY,
                       FALSE,
                       FALSE,
                       FALSE,
                       ANSI_CHARSET,
                       OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE,
                       L"Consolas");
    auto hOldFont = SelectObject(dcDebugWindow, hFont);
    if (hOldFont == NULL)
    {
        goto Failure;
    }

    //
    // Create the regsiter window
    //
    hwndRegisterWindow = CreateWindowEx(0,
                                        L"Simpleator",
                                        L"Register Window",
                                        WS_VISIBLE,
                                        960,
                                        0,
                                        632,
                                        158,
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL);

    //
    // Get the display context of the register window
    //
    dcRegisterWindow = GetDC(hwndRegisterWindow);
    if (dcRegisterWindow == nullptr)
    {
        goto Failure;
    }

    //
    // Get the window position of the register window
    //
    bRes = GetClientRect(hwndRegisterWindow, &rcRegisterWindow);
    if (bRes == FALSE)
    {
        goto Failure;
    }

    //
    // Fully opaque background, black background, red foreground
    //
    SetBkMode(dcRegisterWindow, OPAQUE);
    SetBkColor(dcRegisterWindow, 0);
    SetTextColor(dcRegisterWindow, RGB(255, 0, 0));

    //
    // Get a handle to the OEM fixed width font
    //
    hFont = (HFONT)GetStockObject(OEM_FIXED_FONT);
    if (hFont == nullptr)
    {
        goto Failure;
    }
 
    //
    // Use the OEM fixed width font into this window
    //
    hOldFont = SelectObject(dcRegisterWindow, hFont);
    if (hOldFont == NULL)
    {
        goto Failure;
    }

    //
    // Success path
    //
    return ERROR_SUCCESS;

Failure:
    //
    // Destroy all GUI state
    //
    if (hwndRegisterWindow != nullptr)
    {
        DestroyWindow(hwndRegisterWindow);
    }

    if (hwndRegisterWindow != nullptr)
    {
        DestroyWindow(hwndRegisterWindow);
    }
    if (bClassRegistered)
    {
        UnregisterClass(L"Simpleator", NULL);
    }

    //
    // Return the failure code
    //
    return GetLastError();
}
