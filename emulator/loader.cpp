/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    loader.cpp

Abstract:

    This module implements a simple host-based PE Loader for mapping the images

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

#include "sem.h"

auto
SemLdrLoadImage (
    _In_ PSEM_PARTITION Partition,
    _In_ PWCHAR ImagePath,
    _In_ ULONG_PTR ImageBase,
    _Out_opt_ PULONG_PTR ThreadThunk,
    _Out_opt_ PULONG_PTR EntryPoint
    ) -> HRESULT
{
    WCHAR fileName[MAX_PATH];
    PVOID mapBase;

    //
    // Load the DLL somewhere in our address space
    //
    auto base = LoadLibrary(ImagePath);
    if (base == nullptr)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Get the entrypoint
    //
    auto ntHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    auto entryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;

    //
    // Get the full path
    //
    auto bRes = GetModuleFileName(base, fileName, MAX_PATH);
    if (bRes == FALSE)
    {
        FreeLibrary(base);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Now open our own handle to the mapped file
    //
    auto fileHandle = CreateFile(fileName,
                                 GENERIC_READ | GENERIC_EXECUTE,
                                 FILE_SHARE_READ,
                                 NULL,
                                 OPEN_ALWAYS,
                                 0,
                                 NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        FreeLibrary(base);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Create our own section mapping for it
    //
    auto mapHandle = CreateFileMapping(fileHandle,
                                       NULL,
                                       SEC_IMAGE | PAGE_EXECUTE_READ,
                                       0,
                                       0,
                                       NULL);
    if (mapHandle == INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
        FreeLibrary(base);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Now re-map it again into the hypervisor
    //
    auto hr = SemMmMapGuestImage(Partition,
                                 mapHandle,
                                 ImageBase,
                                 ntHeader->OptionalHeader.SizeOfImage,
                                 &mapBase);

    //
    // Close all the handles and free the library -- keeping only the copy
    //
    CloseHandle(fileHandle);
    CloseHandle(mapHandle);
    FreeLibrary(base);
    if (FAILED(hr))
    {
        return hr;
    }

    //
    // Compute the delta between the two images
    //
    auto delta = reinterpret_cast<ULONG_PTR>(base) -
                 reinterpret_cast<ULONG_PTR>(mapBase);

    //
    // Check if this is the system image, or the application image
    //
    if (ThreadThunk == nullptr)
    {
        //
        // Check if the image has an entrypoint
        //
        if (entryPoint != 0)
        {
            *EntryPoint = reinterpret_cast<ULONG_PTR>(mapBase) + entryPoint;
        }
    }
    else
    {
        //
        // It doesn't -- assume this is the system image
        //
        auto thunkAddress = GetProcAddress(base, "LdrInitializeThunk");
        auto startAddress = GetProcAddress(base, "RtlUserThreadStart");
        *EntryPoint = reinterpret_cast<ULONG_PTR>(thunkAddress) - delta;
        *ThreadThunk = reinterpret_cast<ULONG_PTR>(startAddress) - delta;
    }

    //
    // All done
    //
    return hr;
}

