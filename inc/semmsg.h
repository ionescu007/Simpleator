/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    semmsg.h

Abstract:

    This header defines the messages sent accross the Debug Monitor named pipe.

Author:

    Alex Ionescu (@aionescu) 12-Dec-2018 - Initial version

Environment:

    Kernel mode only.

--*/

//
// Message types can be sent between monitor and emulator
//
typedef enum _SEM_MSG_TYPE
{
    SemUpdateRegisters = 0x04030201,
    SemUpdateDebugTrace = 0x08070605,
    SemSystemCall = 0x41414141,
    SemInternalError = 0x0C0B0A09
} SEM_MSG_TYPE;

//
// Payload of a message sent on the pipe
// Note that 8KB is allways allocated on the user stack, but we only actually
// write on the pipe up to the length of the message (string) itself
//
typedef struct _SEM_PIPE_BUFFER_MSG
{
    SEM_MSG_TYPE MessageType;
    union
    {
        CHAR Data[8184];
        struct
        {
            USHORT Index;
            USHORT ArgumentCount;
            NTSTATUS Result;
            ULONG_PTR Arguments[16];
            CHAR Name[32];
        } SystemCall;
        struct
        {
            //
            // These are sorted in the same order as the emulator's array to
            // make transfer a simple memcpy()
            //
            FLOAT128 Rax;
            FLOAT128 Rcx;
            FLOAT128 Rdx;
            FLOAT128 Rbx;
            FLOAT128 Rsp;
            FLOAT128 Rbp;
            FLOAT128 Rsi;
            FLOAT128 Rdi;
            FLOAT128 R8;
            FLOAT128 R9;
            FLOAT128 R10;
            FLOAT128 R11;
            FLOAT128 R12;
            FLOAT128 R13;
            FLOAT128 R14;
            FLOAT128 R15;
            FLOAT128 Rip;
            FLOAT128 Rflags;
            FLOAT128 Es;
            FLOAT128 Cs;
            FLOAT128 Ss;
            FLOAT128 Ds;
            FLOAT128 Fs;
            FLOAT128 Gs;

            FLOAT128 Cr0;
            FLOAT128 Cr2;
            FLOAT128 Cr3;
            FLOAT128 Cr4;
            FLOAT128 Cr8;
        } Registers;
    };
} SEM_PIPE_BUFFER_MSG, *PSEM_PIPE_BUFFER_MSG;
C_ASSERT(sizeof(SEM_PIPE_BUFFER_MSG) == 8 * 1024);
