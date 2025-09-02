
#pragma once

#include "ntifs.h"
#include "ntddk.h"
#include "Storport.h"  //for using STORPORT storage port driver
#include "NTDDSCSI.H"  //for using SCSIPORT storage port driver
#include "ntimage.h"
#include "Common.hpp"

IO_COMPLETION_ROUTINE IrpCompletionRoutine;
KIPI_BROADCAST_WORKER CallIpiBroadcastFunction;

extern "C"
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader (
    __in PVOID Base
    );

typedef BOOLEAN (*lpfnIoIs32bitProcess)(IN PIRP Irp OPTIONAL);

__checkReturn
NTSTATUS
GetSectionAddress (
    __in DWORD_PTR BaseAddress,
    __in PCHAR Text,
    __in USHORT TextLength,
    __inout PULONG SectionSize,
    __inout PULONG_PTR Address
    );

__checkReturn
NTSTATUS
ScanDriverSection (
    __in PCHAR SectionName,
    __in USHORT SectionNameLength,
    __in DWORD_PTR DriverBase, 
    __in ULONG Magic,
    __in ULONG Distance,
    __out PULONG_PTR Address
    );

__checkReturn
NTSTATUS
Is64bitProcess (
    __in PEPROCESS Process,
    __out PBOOLEAN Is64Bit
    );

__checkReturn
NTSTATUS
ToggleNormalIoPath (
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN Enable
    );

__checkReturn
NTSTATUS
SendSrbIrp (
    __in PDEVICE_OBJECT DiskDeviceObject,
    __in UCHAR SrbFunction,
    __in ULONG SrbFlags
    );

ULONG_PTR
CallIpiBroadcastFunction (
    __in ULONG_PTR Argument
    );

__checkReturn
NTSTATUS
GetUserBuffer (
    __in PVOID UserBuffer,
    __in ULONG UserBufferLength,
    __out PMDL* Mdl,
    __out PVOID* SystemAddress,
    __in BOOLEAN Write
    );

__checkReturn
NTSTATUS
PrepareForPatch (
    __in PVOID VirtualAddress,
    __in ULONG Size,
    __out PMDL* Mdl,
    __out PVOID* SystemAddress
    );

__checkReturn
NTSTATUS
GetImportAddressEntry64 (
    __in DWORD_PTR BaseAddress,
    __in PCHAR ModuleName,
    __in PCHAR FunctionName,
    __out PVOID* Address
    );