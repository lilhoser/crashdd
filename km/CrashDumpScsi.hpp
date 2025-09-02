
#pragma once

#include "Common.hpp"
#include "CommonCrashDump.hpp"
#include "Helper.hpp"

//
// Magic Byte Definitions
//
// Found simply by searching the disassembly in IDA for
// patterns that uniquely identify the target code or data.
//
// Diskdump.sys - win 8 
//
const ULONG DISKDUMP_IOISSUE_MAGIC_32 = 0xfb801375; //jnz short loc_11C77 / cmp ScsiOp, 28h (partial, in little endian)
const ULONG DISKDUMP_IOISSUE_DISTANCE_UP_32 = 0x14;
const ULONG DISKDUMP_IOISSUE_MAGIC_64 = 0x28f98041; //cmp r9b, 28h (little endian)
const ULONG DISKDUMP_IOISSUE_DISTANCE_UP_64 = 0x31;
//
// diskdump.sys - Win 7 and prior
//
const ULONG DISKDUMP_STARTIO_MAGIC_32 = 0xC00C46F6; //test byte ptr[esi+0xC], 0xC0 (in little endian)
const ULONG DISKDUMP_STARTIO_MAGIC_64 = 0xC00C41F6; //test byte ptr[rcx+0xC], 0xC0 (in little endian)
const ULONG DISKDUMP_STARTIO_DISTANCE_UP_32 = 0x14; //32-bit distance to function start
const ULONG DISKDUMP_STARTIO_DISTANCE_UP_64 = 0x6;  //actually less than 32-bit bc instruction is in different place!

typedef NTSTATUS (*PDRIVER_EXECUTE_SRB) (
    __in SCSI_REQUEST_BLOCK* Srb
    );

typedef NTSTATUS (*PDRIVER_STARTIO_CUSTOM) (
    __in SCSI_REQUEST_BLOCK* Srb
    );

typedef struct _DISK_DUMP_IO_ISSUE_ARGUMENTS
{
    ULONG Action;
    UCHAR ScsiOp;
    PLARGE_INTEGER Offset;
    PMDL Mdl;
} DISK_DUMP_IO_ISSUE_ARGUMENTS, *PDISK_DUMP_IO_ISSUE_ARGUMENTS;

typedef struct _SCSI_IPI_REQUEST
{
    PVOID Function;
    KNOWN_OS OperatingSystem;

    union 
    {
        PSCSI_REQUEST_BLOCK Srb;
        PDISK_DUMP_IO_ISSUE_ARGUMENTS IoIssueArguments;
    } u;
} SCSI_IPI_REQUEST, *PSCSI_IPI_REQUEST;

//
// MASM CALL PROXIES
// 
#ifdef _WIN64

extern "C"
ULONG
StartIoProxyCall64 (
    PVOID Function,
    PVOID Argument
    );

extern "C"
ULONG
DiskDumpIoIssueProxyCall64 (
    PVOID Function,
    ULONG Action,
    UCHAR ScsiOp,
    PVOID Offset,
    PVOID Mdl
    );

#else

extern "C"
ULONG
StartIoProxyCall32 (
    PVOID Function,
    PVOID Argument
    );

extern "C"
ULONG
DiskDumpIoIssueProxyCall32 (
    PVOID Function,
    ULONG Action,
    UCHAR ScsiOp,
    PVOID Offset,
    PVOID Mdl
    );
#endif

//
// Function prototypes
//
__checkReturn
NTSTATUS
CrashScsiRead (
    __in PCRASHDD_EXTENSION Extension,
    __in PCRASH_DUMP_STATE State
    );

__checkReturn
NTSTATUS
CrashScsiGetIoFunction (
    __in PCRASHDD_EXTENSION Extension,
    __in PCRASH_DUMP_STATE State
    );

VOID
CrashScsiBuildReadSrb (
    __in PCRASH_DUMP_STATE State,
    __inout PSCSI_REQUEST_BLOCK Srb,
    __in PVOID Buffer,
    __in ULONGLONG Offset,
    __in ULONG Size
    );

ULONG_PTR
CrashScsiIpiBroadcastSendIoRequest (
    __in ULONG_PTR Argument
    );