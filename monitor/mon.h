/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    monitor.h

Abstract:

    This is the main header file for the Simple Emulator's Debug Monitor.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

//
// SDK Headers
//
#pragma once
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

//
// Internal headers shared with the monitor
//
#include <semdef.h>
#include <semmsg.h>

//
// VT-100 Codes
//
#define ESC "\x1b"
#define CSI "\x1b["
#define OSC "\x1b]"

//
// Size of the debug monitor window
//
#define DEBUG_MONITOR_WINDOW_TOP    450
#define DEBUG_MONITOR_WINDOW_WIDTH  980
#define DEBUG_MONITOR_WINDOW_HEIGHT 768

//
// UI Functions
//
auto
UpdateDebugMonitor (
    _In_ PCHAR DebugMessage,
    _In_ ULONG DebugMessageLength
)->VOID;

auto
UpdateRegisterWindow (
    _In_ PSEM_PIPE_BUFFER_MSG Msg
)->VOID;

auto
SemCreateDebuggerWindows (
    VOID
)->HRESULT;

