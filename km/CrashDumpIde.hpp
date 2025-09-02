#pragma once

#include "Common.hpp"
#include "CommonCrashDump.hpp"
#include "ata.h"
#include "irb.h"       //for using ATAPORT storage port driver
#include "Helper.hpp"

//
// Pick an IDE method, both are experimental.
// 1 or 2.
//
static int IDE_METHOD = 1;

//
// Magic Byte Definitions
//
// Found simply by searching the disassembly in IDA for
// patterns that uniquely identify the target code or data.
//
// dumpata.sys - IDE/ATA x86 and x64
//
const ULONG DUMPATA_DISPATCHCRB_MAGIC_32 = 0xFFFC7BE8; //push _DumpExtension / call _IdeDumpCompletionDpc (partial, in little endian)
const ULONG DUMPATA_DISPATCHCRB_MAGIC_64 = 0x25E80000; //mov rcx, cs:DumpExtension / call IdeDumpCompletionDpc (partial, in little endian)
const ULONG DUMPATA_DISPATCHCRB_DISTANCE_UP_32 = 0xB4;
const ULONG DUMPATA_DISPATCHCRB_DISTANCE_UP_64 = 0x15C;
const ULONG DUMPATA_IDEDUMPWAITONREQUEST_MAGIC_32 = 0xFFFA6BE8; //push 0x3E8 / call _IdeDumpPollInterrupt (partial, in little endian)
const ULONG DUMPATA_IDEDUMPWAITONREQUEST_MAGIC_64 = 0xA090FF41; //mov ecx, 0xa / call qword ptr [r8+6a0] (partial, in little endian)
const ULONG DUMPATA_IDEDUMPWAITONREQUEST_DISTANCE_UP_32 = 0x10;
const ULONG DUMPATA_IDEDUMPWAITONREQUEST_DISTANCE_UP_64 = 0x42;
const ULONG DUMPATA_DEVEXT_CRB_OFFSET_32 = 0x120;  //the Crb offsets are from dumpata!IdeDumpWritePending
const ULONG DUMPATA_DEVEXT_CRB_OFFSET_64 = 0x1C0;
const ULONG DUMPATA_DEVEXT_IRB_OFFSET_32 = 0x288;  //the Irb and MDL offsets are reversed out of 
const ULONG DUMPATA_DEVEXT_IRB_OFFSET_64 = 0x3E8;  //dumpata!DispatchCrb
const ULONG DUMPATA_DEVEXT_MDL_OFFSET_32 = 0x50;
const ULONG DUMPATA_DEVEXT_MDL_OFFSET_64 = 0x88;
const ULONG DUMPATA_DEVEXT_CHANNEL_OFFSET_32 = 0x8A;  //the channel, targetid and lun offsets are reversed out of
const ULONG DUMPATA_DEVEXT_CHANNEL_OFFSET_64 = 0xEA;  //dumpata.sys!IdeDumpSetupWriteCrb
const ULONG DUMPATA_DEVEXT_TARGETID_OFFSET_32 = 0x45D;
const ULONG DUMPATA_DEVEXT_TARGETID_OFFSET_64 = 0x6A9;
const ULONG DUMPATA_DEVEXT_LUN_OFFSET_32 = 0x45E;
const ULONG DUMPATA_DEVEXT_LUN_OFFSET_64 = 0x6AA;
const INT DUMPATA_DEVEXT_COMPLETION_CALLBACK_OFFSET = -4; //0x4; //should be same across x86/x64

typedef struct _IDE_IPI_REQUEST
{
    KNOWN_OS OperatingSystem;
    PIDE_REQUEST_BLOCK Irb;
    ULONG_PTR DumpExtension;
    PVOID Crb;
    PVOID IoFunctionPointer;
    PVOID DumpWaitOnRequest;
} IDE_IPI_REQUEST, *PIDE_IPI_REQUEST;

typedef NTSTATUS (*PDISPATCH_CRB) (
    PVOID crb
    );
typedef NTSTATUS (*PIDEDUMPWAITONREQUEST) (
    PVOID crb,
    INT numWaits
    );

KIPI_BROADCAST_WORKER CrashIdeIpiSendRequestToPortDriver;
KIPI_BROADCAST_WORKER CrashIdeIpiSendRequestToMiniportDriver;

__checkReturn
NTSTATUS
CrashIdeRead (
    __in PCRASHDD_EXTENSION Extension,
    __in PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
CrashIdeBuildReadIrb (
    __in PCRASHDD_EXTENSION Extension,
    __in PCRASH_DUMP_STATE State,
    __inout PIDE_REQUEST_BLOCK Irb,
    __out PULONG_PTR Crb
    );

__checkReturn
NTSTATUS
CrashIdeGetIoFunction (
    __in PCRASHDD_EXTENSION Extension,
    __in PCRASH_DUMP_STATE State
    );

PVOID
CrashIdeCrbCompletionCallback (
    __in PVOID Crb
    );

ULONG_PTR
CrashIdeIpiSendRequestToPortDriver (
    __in ULONG_PTR Argument
    );

ULONG_PTR
CrashIdeIpiSendRequestToMiniportDriver (
    __in ULONG_PTR Argument
    );