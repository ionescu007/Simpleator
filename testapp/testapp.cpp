/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    testapp.cpp

Abstract:

    This module implements a simple test command line console application

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include <Windows.h>
#include <stdio.h>

auto
wmain (
    _In_ INT ArgumentCount,
    _In_ PWCHAR Arguments[]
    ) -> INT
{
    //
    // Just print hello and exit
    //
    wprintf(L"Hello World: %d %s\n", ArgumentCount, Arguments[0]);
    return 0;
}
