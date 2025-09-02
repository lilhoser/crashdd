
#pragma once

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "../km/CommonUser.hpp"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

//
// Typedefs
//
typedef enum _INPUT_ERROR_CODE
{
    TooFewArguments,
    TooManyArguments,
    InvalidDeviceName,
    InvalidOutputFile,
    InvalidArgument,
    InvalidReadOffset,
    InvalidReadSize
} INPUT_ERROR_CODE;

//
// Function prototypes
//
INT
wmain (
    __in INT Argc, 
    __in PWCHAR Argv[]
    );

ULONG
CrashDumpRead (
    __in PCRASHDD_REQUEST Request,
    __out PULONG BytesRead
    );

VOID
Usage (
    INPUT_ERROR_CODE Error
    );

VOID
PrintPhysicalDrives (
    VOID
    );
