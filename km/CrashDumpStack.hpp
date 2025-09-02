
#pragma once

#include "ntifs.h"
#include "ntddk.h"
#include "Common.hpp"
#include "CommonCrashDump.hpp"
#include "CrashDumpScsi.hpp"
#include "CrashDumpIde.hpp"
#include "Helper.hpp"

static const wchar_t* g_DefaultDeviceName = L"\\??\\PhysicalDrive0";
static const wchar_t* g_DumpPrefix = L"dump_";
static const int g_DumpPrefixLength = 5;

//
// Internal functions
//
__checkReturn
NTSTATUS 
CrashDumpStackRead (
    __in PCRASHDD_EXTENSION Extension
    );

__checkReturn
NTSTATUS
GetDumpDriverImageInfo (
    __inout PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
LocateCrashDumpDrivers (
    __inout PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
LocateCrashDumpDriversWithDumpPointers (
    __inout PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
GetDiskDeviceObject (
    __inout PDEVICE_OBJECT* DeviceObject
    );

__checkReturn
NTSTATUS
GetDiskDeviceName (
    __in PCRASHDD_EXTENSION Extension,
    __inout PUNICODE_STRING Name
    );

__checkReturn
NTSTATUS
GetDiskDeviceInformation (
    __in PCRASHDD_EXTENSION Extension,
    __inout PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
GetDumpMiniportDriverName (
    __in PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
GetDumpPortDriverName (
    __in PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
InitializeDumpInitBlock (
    __inout PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
InitializeCrashDumpState (
    __in PCRASHDD_EXTENSION Extension,
    __inout PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
GetDumpPointers (
    __in PCRASH_DUMP_STATE State,
    __inout PVOID Buffer,
    __in ULONG InputSize,
    __in ULONG OutputSize
    );

__checkReturn
NTSTATUS
PatchDumpPortDriver (
    __in PCRASH_DUMP_STATE State,
    __in BOOLEAN Is64bit,
    __in BOOLEAN Patch
    );

ULONG_PTR
IpiBroadcastCallDumpDriverEntryPoints (
    __in ULONG_PTR Argument
    );

VOID
NTAPI
DummyPoSetHiberRange (
    IN PVOID HiberContext,
    IN ULONG Flags,
    IN OUT PVOID StartPage,
    IN ULONG Length,
    IN ULONG PageTag 
    );