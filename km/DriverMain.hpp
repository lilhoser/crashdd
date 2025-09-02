
#pragma once

#include "ntifs.h"
#include "ntddk.h"
#include "Common.hpp"
#include "Helper.hpp"
#include "CrashDumpStack.hpp"

static const WCHAR crashddDeviceNameLink[]  = L"\\DosDevices\\crashdd";

//
// Function definitions
//
extern "C" {

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD Unload;
DRIVER_DISPATCH DispatchControl;

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );

VOID
Unload (
    __in PDRIVER_OBJECT DriverObject
    );

NTSTATUS
DispatchControl (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    );

__checkReturn
NTSTATUS
InitializeDeviceExtension (
    __inout PCRASHDD_EXTENSION Extension
    );
}