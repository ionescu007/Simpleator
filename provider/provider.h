/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    provider.h

Abstract:

    This is the main header for the RS5/19H1 System Call Provider

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
#include <winternl.h>
#include <strsafe.h>

//
// Internal NT emulation data structures (undocumented)
//
#include "ntemu.h"

//
// Internal header shared with all SEM components
//
#include "semdef.h"

//
// Internal header shared with the provider
//
typedef PVOID PSEM_PARTITION;
#include "semprov.h"
