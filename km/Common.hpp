
#pragma once

#include "ntifs.h"
#include "ntddk.h"
#include "CommonUser.hpp"

#define LODWORD(ll) ((ULONG)(ll))
#define HIDWORD(ll) ((ULONG)(((ULONGLONG)(ll) >> 32) & 0xFFFFFFFF))
#define LOWORD(l) ((USHORT)(l))
#define HIWORD(l) ((USHORT)(((ULONG)(l) >> 16) & 0xFFFF))
#define LOBYTE(w) ((UCHAR)(w))
#define HIBYTE(w) ((UCHAR)(((USHORT)(w) >> 8) & 0xFF))
#define CRASHDD_TAG 'ddrc'

//
// Structure definitions
//
typedef enum _KNOWN_OS
{
    Win2k = 0xa,
    WinXPSp23 = 0xb,
    Win2k3sp2 = 0xc,
    WinVista_Sp2 = 0xd,
    Win7_2008R2_sp1 = 0xe,
    Win8 = 0xf,
    MaxOs
} KNOWN_OS;

typedef struct _IPI_CALL_ARGUMENT
{
    volatile LONG Barrier;
    PVOID Context;
    PKIPI_BROADCAST_WORKER Callback;
} IPI_CALL_ARGUMENT, *PIPI_CALL_ARGUMENT;

typedef struct _CRASHDD_EXTENSION
{
    PDRIVER_OBJECT DriverObject;
    KNOWN_OS OperatingSystem;
    BOOLEAN Is64bit;
    ULONG DriverObjectModuleListOffset;  // DRIVER_OBJECT.ModuleList undocumented offset
    PCRASHDD_REQUEST UserRequest;
} CRASHDD_EXTESION, *PCRASHDD_EXTENSION;

#ifdef DBG
#define DBGPRINT(Format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0xFFFFFFFF, Format, __VA_ARGS__);
#else
#define DBGPRINT(Format, ...)
#endif