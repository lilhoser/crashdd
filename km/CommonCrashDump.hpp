
#pragma once

#include "NTDDSCSI.H"  //for using SCSIPORT storage port driver
#include "Storport.h"  //for using STORPORT storage port driver
#include <ntdddisk.h>  //for DRIVE_GEOMETRY_EX

#define IO_DUMP_COMMON_BUFFER_SIZE 0x10000 // limits imposed by diskdump!DriverEntry
#define IO_DUMP_NUMBER_OF_COMMON_BUFFERS 2
#define IO_DUMP_MAXIMUM_TRANSFER_SIZE \
        (IO_DUMP_COMMON_BUFFER_SIZE * IO_DUMP_NUMBER_OF_COMMON_BUFFERS) // 64kb * 2

//
// Magic Byte Definitions
//
// Found simply by searching the disassembly in IDA for
// patterns that uniquely identify the target code or data.
//
// diskdump.sys - SCSI/Storport x86
//
const ULONG DISKDUMP_PATCH_BYTES_MAGIC_32 = 0x588e8966; // mov [esi+258h], cx (little endian)
const ULONG DISKDUMP_PATCH_BYTES_LENGTH_32 = 0x15;
const ULONG DISKDUMP_DEVEXT_OFFSET_32 = 0x10;
const ULONG DISKDUMP_DEVEXT_OFFSET_64 = 0x18;
const ULONG DISKDUMP_DEVEXT_MDL_OFFSET_32 = 0xD0;
const ULONG DISKDUMP_DEVEXT_MDL_OFFSET_64 = 0x118;

//
// Dump driver callback routines used by kernel/crashdmp.sys
// for disk I/O during crash dump.
// Need these typedefs for the structure def below.
//
typedef
VOID
(*PSTALL_ROUTINE) (
    IN ULONG Delay
    );

typedef
BOOLEAN
(*PDUMP_DRIVER_OPEN) (
    IN LARGE_INTEGER PartitionOffset
    );

typedef
NTSTATUS
(*PDUMP_DRIVER_WRITE) (
    IN PLARGE_INTEGER DiskByteOffset,
    IN PMDL Mdl
    );

typedef
VOID
(*PDUMP_DRIVER_FINISH) (
    VOID
    );

typedef
NTSTATUS
(*PDUMP_DRIVER_WRITE_PENDING) (
    IN LONG Action,
    IN PLARGE_INTEGER DiskByteOffset,
    IN PMDL Mdl,
    IN PVOID LocalData
    );

#pragma warning(disable:4201) //nameless struct/union

typedef struct _LDR_DATA_TABLE_ENTRY
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     USHORT LoadCount;
     USHORT TlsIndex;
     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     PVOID EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//
// This is the information passed from the system to the disk dump driver
// during the driver's initialization.
//
typedef struct _DUMP_INITIALIZATION_CONTEXT {
    ULONG Length;
    ULONG Reserved;
    PVOID MemoryBlock;
    PVOID CommonBuffer[2];
    PHYSICAL_ADDRESS PhysicalAddress[2];
    PSTALL_ROUTINE StallRoutine;
    PDUMP_DRIVER_OPEN OpenRoutine;
    PDUMP_DRIVER_WRITE WriteRoutine;
    PDUMP_DRIVER_FINISH FinishRoutine;
#ifdef _WIN64
    PADAPTER_OBJECT AdapterObject;
#else
    struct _ADAPTER_OBJECT * AdapterObject;
#endif
    PVOID MappedRegisterBase;
    PVOID PortConfiguration;
    BOOLEAN CrashDump;
    ULONG MaximumTransferSize;
    ULONG CommonBufferSize;
    PSCSI_ADDRESS TargetAddress;
    PDUMP_DRIVER_WRITE_PENDING WritePendingRoutine;
    ULONG PartitionStyle;
    union {
        struct {
            ULONG Signature;
            ULONG CheckSum;
        } Mbr;
        struct {
            GUID DiskId;
        } Gpt;
    } DiskInfo;
} DUMP_INITIALIZATION_CONTEXT, *PDUMP_INITIALIZATION_CONTEXT;

typedef struct _DUMP_STACK_CONTEXT {
    DUMP_INITIALIZATION_CONTEXT Init;
    LARGE_INTEGER               PartitionOffset;
    PVOID                       DumpPointers;
    ULONG                       PointersLength;
    PWCHAR                      ModulePrefix;
    LIST_ENTRY                  DriverList;
    ANSI_STRING                 InitMsg;
    ANSI_STRING                 ProgMsg;
    ANSI_STRING                 DoneMsg;
    PVOID                       FileObject;
    enum _DEVICE_USAGE_NOTIFICATION_TYPE    UsageType;
} DUMP_STACK_CONTEXT, *PDUMP_STACK_CONTEXT;

//
// This is a hack to not have to build to win8 to use this struct
// which is defined in the WDK headers.
//
typedef struct _DUMP_POINTERS_EX_V3
{
    DUMP_POINTERS_EX DumpPointersEx;
    //
    // Start of DUMP_POINTERS_EX_V3 specific fields
    //
    ULONG dwPortFlags;
    ULONG MaxDeviceDumpSectionSize;
    ULONG MaxDeviceDumpLevel;
    ULONG MaxTransferSize;
    PVOID AdapterObject;
    PVOID MappedRegisterBase;
    PBOOLEAN DeviceReady;
} DUMP_POINTERS_EX_V3, *PDUMP_POINTERS_EX_V3;

//
// A partially reconstructed version of new structure
// passed to the dump port driver in windows 8 (no longer DumpInit)
//
typedef struct _WIN8_CONTEXT
{
   _DUMP_STACK_CONTEXT DumpStack;
   union {
   _DUMP_POINTERS DumpPointers;
   _DUMP_POINTERS_EX DumpPointersEx;
   } u;
   UCHAR Unknown[0xA0];
} WIN8_CONTEXT, *PWIN8_CONTEXT;

//
// Internal structure used to hold crash dump info
//
typedef struct _DISK_DEVICE_INFO
{
    UNICODE_STRING Name;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject;
    PDUMP_POINTERS DumpPointers;
    PDUMP_POINTERS_EX_V3 DumpPointersEx;
    BOOLEAN IsScsiDevice;
    DISK_GEOMETRY_EX DiskGeometry;
} DISK_DEVICE_INFO,  *PDISK_DEVICE_INFO;

typedef struct _DUMP_PORT_DRIVER_INFO
{
    UNICODE_STRING Name;
    ULONG_PTR BaseAddress;
    PDRIVER_INITIALIZE EntryPoint;
    ULONG_PTR Extension;
    ULONG_PTR IoFunctionPointer;
    PMDL PatchMdl;
    UCHAR PatchOriginalBytes[DISKDUMP_PATCH_BYTES_LENGTH_32];
    ULONGLONG PatchOriginalImport;
} DUMP_PORT_DRIVER_INFO, *PDUMP_PORT_DRIVER_INFO;

typedef struct _DUMP_MINIPORT_DRIVER_INFO
{
    UNICODE_STRING Name;
    ULONG_PTR BaseAddress;
    PDRIVER_INITIALIZE EntryPoint;
} DUMP_MINIPORT_DRIVER_INFO, *PDUMP_MINIPORT_DRIVER_INFO;

typedef struct _CRASH_DUMP_STATE
{
    DISK_DEVICE_INFO DiskDeviceInformation;
    PWIN8_CONTEXT DumpInit;
    DUMP_PORT_DRIVER_INFO DumpPortDriver;
    DUMP_MINIPORT_DRIVER_INFO DumpMiniportDriver;
    PLDR_DATA_TABLE_ENTRY PsLoadedModuleList;
} CRASH_DUMP_STATE, *PCRASH_DUMP_STATE;