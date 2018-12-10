/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    semdef.h

Abstract:

    This header contains shared definitions for all Simple Emulator components.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

//
// Some simple size constants to make things easier
//
static constexpr auto s_1MB = 1ULL * 1024 * 1024;
static constexpr auto s_1GB = 1ULL * 1024 * 1024 * 1024;
static constexpr auto s_256GB = 256ULL * s_1GB;
static constexpr auto s_512GB = 512ULL * s_1GB;

//
// OS Constants for memory layout setup
//
static const auto s_UserSharedData = reinterpret_cast<PVOID>(0x7FFE0000ULL);
static const auto s_UserSharedDataEnd = reinterpret_cast<PVOID>(0x7FFF0000ULL);
static const auto s_LowestValidAddress = reinterpret_cast<PVOID>(0x10000ULL);
static const auto s_HighestValidAddress = reinterpret_cast<PVOID>(s_256GB - 1);

