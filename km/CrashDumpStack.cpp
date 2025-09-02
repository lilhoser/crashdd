
#include "CrashDumpStack.hpp"

#pragma warning(disable:4055) // casting data pointer to func pointer

///=========================================================================
/// FreeCrashDumpState()
///
/// <summary>
/// Releases resources in a CRASH_DUMP_STATE structure.
/// </summary>
/// <returns>Nothing</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
VOID
FreeCrashDumpState (
    __inout PCRASH_DUMP_STATE State
    )
{
    if (State == NULL)
    {
        return;
    }

    //
    // Free init struct
    //
    if (State->DumpInit != NULL)
    {
        if (State->DumpInit->DumpStack.Init.TargetAddress != NULL)
        {
            ExFreePoolWithTag(State->DumpInit->DumpStack.Init.TargetAddress, CRASHDD_TAG);
            State->DumpInit->DumpStack.Init.TargetAddress = NULL;
        }

        if (State->DumpInit->DumpStack.Init.MemoryBlock != NULL)
        {
            ExFreePoolWithTag(State->DumpInit->DumpStack.Init.MemoryBlock, CRASHDD_TAG);
            State->DumpInit->DumpStack.Init.MemoryBlock = NULL;
        }

        ExFreePoolWithTag(State->DumpInit, CRASHDD_TAG);
        State->DumpInit = NULL;
    }

    //
    // Free dump pointers
    if (State->DiskDeviceInformation.DumpPointers != NULL)
    {
        ExFreePoolWithTag(State->DiskDeviceInformation.DumpPointers, CRASHDD_TAG);
        State->DiskDeviceInformation.DumpPointers = NULL;
    }

    if (State->DiskDeviceInformation.DumpPointersEx != NULL)
    {
        ExFreePoolWithTag(State->DiskDeviceInformation.DumpPointersEx, CRASHDD_TAG);
        State->DiskDeviceInformation.DumpPointersEx = NULL;
    }
    
    //
    // Free port/miniport name buffers
    //
    if (State->DumpPortDriver.Name.Buffer != NULL)
    {
        ExFreePoolWithTag(State->DumpPortDriver.Name.Buffer, CRASHDD_TAG);
        State->DumpPortDriver.Name.Buffer = NULL;
    }

    if (State->DumpMiniportDriver.Name.Buffer != NULL)
    {
        ExFreePoolWithTag(State->DumpMiniportDriver.Name.Buffer, CRASHDD_TAG);
        State->DumpMiniportDriver.Name.Buffer = NULL;
    }

    return;
}

///=========================================================================
/// InitializeCrashDumpState()
///
/// <summary>
/// Initializes a CRASH_DUMP_STATE structure.
/// </summary>
/// <returns>NT STATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
InitializeCrashDumpState (
    __in PCRASHDD_EXTENSION Extension,
    __inout PCRASH_DUMP_STATE State
    )
{
    NTSTATUS status;
    PDUMP_INITIALIZATION_CONTEXT init;

    NT_ASSERT(State != NULL);

    RtlZeroMemory(State, sizeof(CRASH_DUMP_STATE));

    //
    // Allocate dump port driver's argument based on OS
    //
    State->DumpInit = (PWIN8_CONTEXT)ExAllocatePoolWithTag(NonPagedPool,
                                        sizeof(WIN8_CONTEXT),
                                        CRASHDD_TAG);

    if (State->DumpInit == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(State->DumpInit, sizeof(WIN8_CONTEXT));    

    init = &State->DumpInit->DumpStack.Init;

    init->TargetAddress = (PSCSI_ADDRESS)ExAllocatePoolWithTag(NonPagedPool,
                                                            sizeof(SCSI_ADDRESS),
                                                            CRASHDD_TAG);
    if (init->TargetAddress == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(init->TargetAddress, sizeof(SCSI_ADDRESS));

    //  
    // Allocate memory for dump pointers
    //
    State->DiskDeviceInformation.DumpPointers = (PDUMP_POINTERS)ExAllocatePoolWithTag(
                                    NonPagedPool, 
                                    sizeof(DUMP_POINTERS), 
                                    CRASHDD_TAG);
    
    if (State->DiskDeviceInformation.DumpPointers == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(State->DiskDeviceInformation.DumpPointers, sizeof(DUMP_POINTERS));

    State->DiskDeviceInformation.DumpPointersEx = (PDUMP_POINTERS_EX_V3)ExAllocatePoolWithTag(
                                    NonPagedPool, 
                                    sizeof(DUMP_POINTERS_EX_V3),
                                    CRASHDD_TAG);
    
    if (State->DiskDeviceInformation.DumpPointersEx == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(State->DiskDeviceInformation.DumpPointersEx, sizeof(DUMP_POINTERS_EX_V3));

    //
    // Store a pointer to PsLoadedModuleList
    //
    if (Extension->DriverObjectModuleListOffset == 0)
    {
        DBGPRINT("crashdd:\tInvalid field offset, can't find PsLoadedModuleList\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    State->PsLoadedModuleList = *((PLDR_DATA_TABLE_ENTRY*)((DWORD_PTR)Extension->DriverObject + 
                        Extension->DriverObjectModuleListOffset));

    if (State->PsLoadedModuleList == NULL)
    {
        DBGPRINT("crashdd:\tPsLoadedModuleList pointer is null\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:

    if (!NT_SUCCESS(status))
    {
        FreeCrashDumpState(State);
    }

    return status;
}

///=========================================================================
/// GetDiskDeviceName()
///
/// <summary>
/// Resolves the dos device symbolic link name for the disk device, if provided
/// by the user; otherwise, determines this name dynamically.
/// </summary>
/// <returns>NT STATUS code</returns>
/// <remarks>
/// Caller must free Name if buffer is non-null on successful return.
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetDiskDeviceName (
    __in PCRASHDD_EXTENSION Extension,
    __inout PUNICODE_STRING Name
    )
{
    UNICODE_STRING linkName;
    OBJECT_ATTRIBUTES oa;
    HANDLE linkObjectHandle;
    NTSTATUS status;
    ULONG returnedLength;
    PMDL mdl;
    PVOID address;
    PVOID userBuffer;
    USHORT userBufferLength;

    NT_ASSERT(Extension != NULL);
    NT_ASSERT(Extension->UserRequest != NULL);
    NT_ASSERT(Name != NULL);
    
    linkObjectHandle = NULL;
    Name->Buffer = NULL;
    Name->Length = 0;
    Name->MaximumLength = 0;
    address = NULL;
    mdl = NULL;
    
    userBuffer = Extension->UserRequest->DeviceName.Buffer;
    userBufferLength = Extension->UserRequest->DeviceName.Length;
    userBufferLength += sizeof(WCHAR);

    //
    // Attempt to resolve user-supplied dos name or use default.
    //
    if (userBuffer != NULL)
    {
        status = GetUserBuffer(userBuffer,
                               userBufferLength,
                               &mdl,
                               &address,
                               FALSE);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("crashdd:\tCould not get user buffer\n");
            goto Exit;
        }

        RtlInitUnicodeString(&linkName, (PWCHAR)address);
    }
    else
    {
        RtlInitUnicodeString(&linkName, g_DefaultDeviceName);
    }

    InitializeObjectAttributes(&oa, &linkName, 0, NULL, NULL);

    //
    // Resolve link name
    //
    status = ZwOpenSymbolicLinkObject(&linkObjectHandle, GENERIC_ALL, &oa);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to open link object for %ws: %08x\n", 
                 linkName.Buffer,
                 status);
        goto Exit;
    }

    status = ZwQuerySymbolicLinkObject(linkObjectHandle, Name, &returnedLength);

    if (status == STATUS_BUFFER_TOO_SMALL)
    {
        Name->Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool,
                                                      returnedLength,
                                                      CRASHDD_TAG);
        if (Name->Buffer == NULL)
        {
            DBGPRINT("crashdd:\tFailed to allocate %lu bytes\n", returnedLength);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        NT_VERIFY(returnedLength < 0xffff);

        Name->MaximumLength = (USHORT)returnedLength;

        status = ZwQuerySymbolicLinkObject(linkObjectHandle, Name, &returnedLength);
            
        if (!NT_SUCCESS(status))
        {
            DBGPRINT("crashdd:\tFailed to query link object for %ws: %08x\n", 
                     linkName.Buffer,
                     status);
            goto Exit;
        }
    }
    else
    {
        DBGPRINT("crashdd:\tFailed to query link object for %ws: %08x\n",
                 linkName.Buffer,
                 status);
        goto Exit;
    }

Exit:

    if (linkObjectHandle != NULL)
    {
        ZwClose(linkObjectHandle);
    }

    if (mdl != NULL)
    {
        __try
        {
             MmUnlockPages(mdl);
        }
        __except(EXCEPTION_CONTINUE_EXECUTION)
        {
            
        }

        IoFreeMdl(mdl);
    }

    if (!NT_SUCCESS(status))
    {
        if (Name->Buffer != NULL)
        {
            ExFreePoolWithTag(Name->Buffer, CRASHDD_TAG);
            Name->Buffer = NULL;
        }
    }

    return status;
}

///=========================================================================
/// GetDiskDeviceInformation()
///
/// <summary>
/// Retrieves information about the input disk device.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetDiskDeviceInformation (
    __in PCRASHDD_EXTENSION Extension,
    __inout PCRASH_DUMP_STATE State
    )
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    HANDLE handle;
    IO_STATUS_BLOCK iostatus;
    NTSTATUS status;
    PFILE_OBJECT fileObject;
    PDEVICE_OBJECT deviceObject;
    PSCSI_ADDRESS scsiAddress;

    NT_ASSERT(Extension != NULL);
    NT_ASSERT(State != NULL);

    handle = NULL;
    fileObject = NULL;
    name.Buffer = NULL;

    status = GetDiskDeviceName(Extension, &name);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to retrieve disk device name: %08x\n", status);
        goto Exit;
    }

    NT_ASSERT(name.Buffer != NULL);

    DBGPRINT("crashdd:\tUsing disk device named %ws\n", name.Buffer);

    InitializeObjectAttributes(&oa, &name, 0, NULL, NULL);

    //
    // Open a handle to the disk device
    //
    status = ZwOpenFile(&handle,
                        FILE_READ_ATTRIBUTES,
                        &oa,
                        &iostatus,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_NON_DIRECTORY_FILE);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to open disk device %ws:  %08x\n", name.Buffer, status);
        goto Exit;
    }

    status = ObReferenceObjectByHandle(handle,
                                       0,
                                       *IoFileObjectType,
                                       KernelMode,
                                       (PVOID*)&fileObject,
                                       NULL);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to get FILE_OBJECT from device handle:  %08x\n", status);
        goto Exit;
    }

    NT_ASSERT(fileObject != NULL);

    State->DiskDeviceInformation.FileObject = fileObject;

    //
    // Get pointer to the top device object in the disk stack
    //
    // NB: If we pass FILE_READ_DATA flag to ZwOpenFile, this gets the device object 
    // for the file system driver "Raw" bc the file system is automatically mounted 
    // and therefore is the top driver in the stack.  If we pass just FILE_READ_ATTRIBUTES, we get
    // the device object for partition filter driver (partFltMgr) driver bc the fs is 
    // not mounted and it is therefore the top.
    // See http://www.osronline.com/showthread.cfm?link=100411
    //
    // *devObj = IoGetRelatedDeviceObject(FileObject); <-- gets either \Driver\Raw or \Driver\PartFltMgr
    //
    // Since we dont want either of those drivers, we will walk the attached device 
    // stack until we get to the bottom.
    //
    State->DiskDeviceInformation.DeviceObject = fileObject->DeviceObject;
    deviceObject = State->DiskDeviceInformation.DeviceObject;

    for (; ;)
    {
        deviceObject = IoGetLowerDeviceObject(deviceObject);

        if (deviceObject == NULL)
        {
            break;
        }

        State->DiskDeviceInformation.DeviceObject= deviceObject;
        ObDereferenceObject(deviceObject);
    }

    DBGPRINT("crashdd:\tDisk device's DeviceObject at %p\n", State->DiskDeviceInformation.DeviceObject);

    //
    // Retrieve a pointer to the field in the init structure we will
    // be using to store the SCSI_ADDRESS data.
    //
    scsiAddress = State->DumpInit->DumpStack.Init.TargetAddress;

    NT_ASSERT(scsiAddress != NULL);

    //
    // Get the scsi address
    //
    status = ZwDeviceIoControlFile(handle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &iostatus,
                                   IOCTL_SCSI_GET_ADDRESS,
                                   NULL,
                                   0,
                                   scsiAddress,
                                   sizeof(SCSI_ADDRESS));

    if (status == STATUS_PENDING)
    {
        ZwWaitForSingleObject(handle,FALSE,NULL);
        status = iostatus.Status;
    }

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to get SCSI address: %08x\n", status);
        goto Exit;
    }

    DBGPRINT("crashdd:\tSCSI address:  LUN=%i, TargetId=%i, PathId=%i, Port=%i\n", 
             scsiAddress->Lun,
             scsiAddress->TargetId,
             scsiAddress->PathId,
             scsiAddress->PortNumber);

    //
    // Get the drive geometry
    //
    status = ZwDeviceIoControlFile(handle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &iostatus,
                                   IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                   NULL,
                                   0,
                                   &State->DiskDeviceInformation.DiskGeometry,
                                   sizeof(State->DiskDeviceInformation.DiskGeometry));

    if (status == STATUS_PENDING)
    {
        ZwWaitForSingleObject(handle,FALSE,NULL);
        status = iostatus.Status;
    }

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to get drive geometry: %08x\n", status);
        goto Exit;
    }

    DBGPRINT("crashdd:\tDrive geometry:\n" \
             "crashdd:\t\tDisk size: %I64u\n" \
             "crashdd:\t\tMedia type: %i\n" \
             "crashdd:\t\tCylinders: %I64u\n" \
             "crashdd:\t\tSectors per track: %lu\n" \
             "crashdd:\t\tTracks per cylinder: %lu\n" \
             "crashdd:\t\tBytes per sector: %lu\n",
             State->DiskDeviceInformation.DiskGeometry.DiskSize.QuadPart,
             State->DiskDeviceInformation.DiskGeometry.Geometry.MediaType,
             State->DiskDeviceInformation.DiskGeometry.Geometry.Cylinders.QuadPart,
             State->DiskDeviceInformation.DiskGeometry.Geometry.SectorsPerTrack,
             State->DiskDeviceInformation.DiskGeometry.Geometry.TracksPerCylinder,
             State->DiskDeviceInformation.DiskGeometry.Geometry.BytesPerSector);

    if (State->DiskDeviceInformation.DiskGeometry.Geometry.BytesPerSector == 0)
    {
        DBGPRINT("crashdd:\tInvalid drive geometry.\n");
        goto Exit;
    }

    NT_ASSERT(State->DiskDeviceInformation.DumpPointers != NULL);
    NT_ASSERT(State->DiskDeviceInformation.DumpPointersEx != NULL);

    //
    // Get dump pointers - first try DUMP_POINTERS_EX (vista+),
    // namely because it contains the DriverList field which we can use later.
    //
    ((PDUMP_POINTERS_EX)State->DiskDeviceInformation.DumpPointersEx)->Header.Version = 2;
    ((PDUMP_POINTERS_EX)State->DiskDeviceInformation.DumpPointersEx)->Header.Size = 0x20;

    status = GetDumpPointers(State, 
                             State->DiskDeviceInformation.DumpPointersEx,
                             sizeof(State->DiskDeviceInformation.DumpPointersEx),
                             sizeof(DUMP_POINTERS_EX_V3));

    //
    // Retry with DUMP_POINTERS (pre-vista)
    //
    if ((status == STATUS_REVISION_MISMATCH) ||
        (((PDUMP_POINTERS_EX)State->DiskDeviceInformation.DumpPointersEx)->Header.Version < 2) ||   
        (((PDUMP_POINTERS_EX)State->DiskDeviceInformation.DumpPointersEx)->Header.Version > 3) ||
        (((PDUMP_POINTERS_EX)State->DiskDeviceInformation.DumpPointersEx)->Header.Size < 0x20) ||
        (((PDUMP_POINTERS_EX)State->DiskDeviceInformation.DumpPointersEx)->Header.Version > 
        sizeof(DUMP_POINTERS_EX_V3)))
    {
        DBGPRINT("crashdd:\tNot using DUMP_POINTERS_EX (%08x)\n", status);

        //
        // Free old dump pointers struct so we know to use this one later on.
        //
        ExFreePoolWithTag(State->DiskDeviceInformation.DumpPointersEx, CRASHDD_TAG);
        State->DiskDeviceInformation.DumpPointersEx = NULL;

        status = GetDumpPointers(State,
                                 State->DiskDeviceInformation.DumpPointers,
                                 sizeof(DUMP_POINTERS),
                                 sizeof(DUMP_POINTERS));

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("crashdd:\tCould not get DUMP_POINTERS (%08x)\n", status);
            goto Exit;
        }
    }
    //
    // Success - free unused pointer
    //
    else if (NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tUsing DUMP_POINTERS_EX\n");

        ExFreePoolWithTag(State->DiskDeviceInformation.DumpPointers, CRASHDD_TAG);
        State->DiskDeviceInformation.DumpPointers = NULL;
    }
    //
    // Some other error - fail
    //
    else
    {
        DBGPRINT("crashdd:\tCould not get available DUMP_POINTERS_EX: %08x\n", status);
        goto Exit;
    }

    //
    // Fill in DUMP_INITIALIZATION_CONTEXT with the info we found
    //
    status = InitializeDumpInitBlock(State);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to initialize DUMP_INITIALIZATION_CONTEXT structure: %08x\n",
                 status);
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:

    if (name.Buffer != NULL)
    {
        ExFreePoolWithTag(name.Buffer, CRASHDD_TAG);
    }

    if (handle != NULL)
    {
        ZwClose(handle);
    }

    if (fileObject != NULL)
    {
        ObDereferenceObject(fileObject);
    }

    return status;
}

///=========================================================================
/// GetDumpPointers()
///
/// <summary>
/// Queries the root disk device to get its DUMP_POINTERS or DUMP_POINTERS_EX 
/// info.  Applicable to both IDE and SCSI.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetDumpPointers (
    __in PCRASH_DUMP_STATE State,
    __inout PVOID Buffer,
    __in ULONG InputSize,
    __in ULONG OutputSize
    )
{
    KEVENT event;
    PIRP irp;
    PIO_STACK_LOCATION ioStackLocation;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;

    NT_ASSERT(State != NULL);
    NT_ASSERT(Buffer != NULL);
    NT_ASSERT(State->DiskDeviceInformation.DeviceObject != NULL);
    NT_ASSERT(State->DiskDeviceInformation.FileObject != NULL);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoBuildDeviceIoControlRequest(IOCTL_SCSI_GET_DUMP_POINTERS,
                                        State->DiskDeviceInformation.DeviceObject,
                                        Buffer,
                                        InputSize,
                                        Buffer,
                                        OutputSize,
                                        FALSE,
                                        &event,
                                        &ioStatusBlock);

    if (irp == NULL)
    {
        status = ioStatusBlock.Status;
        if (NT_SUCCESS(status))
            status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    DBGPRINT("crashdd:\tContacting disk driver to get dump pointers (size %i, %i)...\n",
             InputSize,
             OutputSize);

    ioStackLocation = IoGetNextIrpStackLocation(irp);
    NT_ASSERT(ioStackLocation != NULL);
    ioStackLocation->FileObject = State->DiskDeviceInformation.FileObject;

    status = IoCallDriver(State->DiskDeviceInformation.DeviceObject, irp);

    if (status == STATUS_PENDING)
    {
        DBGPRINT("crashdd:\tWaiting for response from disk device...\n");
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

Exit:

    return status;
}

///=========================================================================
/// InitializeDumpInitBlock()
///
/// <summary>
/// Initializes a DUMP_INITIALIZATION_CONTEXT structure.
/// </summary>
/// <returns>TRUE if successful, false if not.</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
NTSTATUS
InitializeDumpInitBlock (
    __inout PCRASH_DUMP_STATE State
    )
{
    PVOID buffer;
    PHYSICAL_ADDRESS physical;
    INT i;
    NTSTATUS status;
    PDUMP_POINTERS_EX_V3 dumpPointers;
    PDUMP_INITIALIZATION_CONTEXT init;
    PADAPTER_OBJECT adapter;
    ULONG commonBufferSize;
    BOOLEAN allocateCommonBuffers;

    NT_ASSERT(State != NULL);
    NT_ASSERT(State->DumpInit != NULL);
    NT_ASSERT(State->DumpInit->DumpStack.Init.TargetAddress != NULL);

    init = &State->DumpInit->DumpStack.Init;

    RtlCopyMemory(init->TargetAddress,
                  init->TargetAddress,
                  sizeof(SCSI_ADDRESS));

    init->Length = sizeof(DUMP_INITIALIZATION_CONTEXT);
    init->CrashDump = TRUE;
    init->MemoryBlock = ExAllocatePoolWithTag(NonPagedPool,
                                              IO_DUMP_MAXIMUM_TRANSFER_SIZE,
                                              CRASHDD_TAG);
    if (init->MemoryBlock == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(init->MemoryBlock, IO_DUMP_MAXIMUM_TRANSFER_SIZE);

    init->StallRoutine = &KeStallExecutionProcessor;
    init->MaximumTransferSize = IO_DUMP_MAXIMUM_TRANSFER_SIZE;

    if (State->DiskDeviceInformation.DumpPointers != NULL)
    {
        init->AdapterObject = (PADAPTER_OBJECT)State->DiskDeviceInformation.DumpPointers->AdapterObject;
        init->MappedRegisterBase = State->DiskDeviceInformation.DumpPointers->MappedRegisterBase;
        init->PortConfiguration  = State->DiskDeviceInformation.DumpPointers->DumpData;
        allocateCommonBuffers = State->DiskDeviceInformation.DumpPointers->AllocateCommonBuffers;
        commonBufferSize = State->DiskDeviceInformation.DumpPointers->CommonBufferSize;

        //
        // The minimum common buffer size is IO_DUMP_COMMON_BUFFER_SIZE (compatability)
        // This is used by the dump driver for SRB extension, CachedExtension, and sense buffer
        //
        if (commonBufferSize < IO_DUMP_COMMON_BUFFER_SIZE)
        {
            commonBufferSize = IO_DUMP_COMMON_BUFFER_SIZE;
            State->DiskDeviceInformation.DumpPointers->CommonBufferSize = commonBufferSize;
        }
    }
    else
    {
        dumpPointers = State->DiskDeviceInformation.DumpPointersEx;
        init->AdapterObject = (PADAPTER_OBJECT)dumpPointers->AdapterObject;
        init->MappedRegisterBase = dumpPointers->MappedRegisterBase;
        init->PortConfiguration  = dumpPointers->DumpPointersEx.DumpData;
        allocateCommonBuffers = dumpPointers->DumpPointersEx.AllocateCommonBuffers;
        commonBufferSize = dumpPointers->DumpPointersEx.CommonBufferSize;

        //
        // The minimum common buffer size is IO_DUMP_COMMON_BUFFER_SIZE (compatability)
        // This is used by the dump driver for SRB extension, CachedExtension, and sense buffer
        //
        if (commonBufferSize < IO_DUMP_COMMON_BUFFER_SIZE)
        {
            commonBufferSize = IO_DUMP_COMMON_BUFFER_SIZE;
            dumpPointers->DumpPointersEx.CommonBufferSize = commonBufferSize;
        }
    }

    adapter = init->AdapterObject;
    init->CommonBufferSize = commonBufferSize;

    if (allocateCommonBuffers != FALSE)
    {
        physical.QuadPart = 0xFFFFFF;

        for (i = 0; i < IO_DUMP_NUMBER_OF_COMMON_BUFFERS; i++) 
        {
            if (init->AdapterObject != NULL) 
            {
                buffer = HalAllocateCommonBuffer(init->AdapterObject,
                                                 commonBufferSize,
                                                 &physical,
                                                 FALSE);
            }
            else
            {
                buffer = MmAllocateContiguousMemory(commonBufferSize, physical);
                    
                if (buffer == NULL)
                {
                    buffer = MmAllocateNonCachedMemory(commonBufferSize);
                }

                physical = MmGetPhysicalAddress(buffer);
            }

            if (buffer == NULL)
            {
                status = STATUS_UNSUCCESSFUL;
                DBGPRINT("crashdd:\tCould not allocate common buffers for dump!\n");
                goto Exit;
            }

            init->CommonBuffer[i] = buffer;
            init->PhysicalAddress[i] = physical;
        }
    }

    status = STATUS_SUCCESS;

Exit:

    return status;
}

///=========================================================================
/// LocateCrashDumpDrivers()
///
/// <summary>
/// Locates the dump port and miniport crash dump drivers in memory.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
LocateCrashDumpDrivers (
    __inout PCRASH_DUMP_STATE State
    )
{
    NTSTATUS status;

    NT_ASSERT(State != NULL);

    //
    // Try to load the drivers using DUMP_POINTERS_EX trick
    //
    if (State->DiskDeviceInformation.DumpPointersEx != NULL)
    {
        status = LocateCrashDumpDriversWithDumpPointers(State);
    
        if (NT_SUCCESS(status))
        {
            goto Exit;
        }

        DBGPRINT("crashdd:\tFailed to use available DumpPointersEx.DriverList\n");
    }

    //
    // Load the drivers manually by scanning PsLoadedModuleList
    //
    DBGPRINT("crashdd:\tAttempting to locate drivers manually...\n");

    //
    // If a miniport name was not explicitly provided, find it dynamically.
    //
    if (State->DumpMiniportDriver.Name.Buffer == NULL)
    {
        status = GetDumpMiniportDriverName(State);

        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        NT_ASSERT(State->DumpMiniportDriver.Name.Buffer != NULL);
    }

    //
    // If a port driver name was not explicitly provided, find it dynamically.
    //
    if (State->DumpPortDriver.Name.Buffer == NULL)
    {
        status = GetDumpPortDriverName(State);

        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        NT_ASSERT(State->DumpPortDriver.Name.Buffer != NULL);
    }

    //
    // Store the entry points and base addresses of the port drivers
    // for later use.
    //
    status = GetDumpDriverImageInfo(State);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tCould not locate dump driver image information: %08x\n",
                 status);
        goto Exit;
    }

    //
    // TODO:  Do addt'l validation that these are in fact the drivers we want.
    //

    status = STATUS_SUCCESS;

    DBGPRINT("crashdd:\tDump driver information:\n");
    DBGPRINT("crashdd:\t\tdump port driver %ws at %p, EP %p\n", 
             State->DumpPortDriver.Name.Buffer,
             State->DumpPortDriver.BaseAddress,
             State->DumpPortDriver.EntryPoint);
    DBGPRINT("crashdd:\t\tdump miniport driver %ws at %p, EP %p\n", 
             State->DumpMiniportDriver.Name.Buffer,
             State->DumpMiniportDriver.BaseAddress,
             State->DumpMiniportDriver.EntryPoint);

Exit:

    return status;
}

///=========================================================================
/// LocateCrashDumpDriversWithDumpPointers()
///
/// <summary>
/// Locates the dump port and miniport crash dump drivers in memory using
/// the special DUMP_POINTERS_EX trick.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// Walks the crash dump driver stack stored in the DUMP_POINTERS_EX structure 
/// obtained from the normal I/O path port driver via IOCTL_SCSI_GET_DUMP_POINTERS.
///
/// Note that this often fails because the port driver stores dump_diskdump.sys
/// as the dump port driver when it's mapped into memory as dump_storport.sys.
/// This is OK, as our fallback technique (look for static names) will work.
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
LocateCrashDumpDriversWithDumpPointers (
    __inout PCRASH_DUMP_STATE State
    )
{
    NTSTATUS status;
    PDUMP_DRIVER dumpDriver;
    USHORT i, size;
    PUNICODE_STRING target;
    PSINGLE_LIST_ENTRY entry;

    NT_ASSERT(State != NULL);
    NT_ASSERT(State->DiskDeviceInformation.DumpPointersEx != NULL);

    i = 0;

    //
    // The DumpPointersEx.DriverList field is an array of pointers that each
    // point to a null-term driver name and base name
    //
    entry = (PSINGLE_LIST_ENTRY)State->DiskDeviceInformation.DumpPointersEx->DumpPointersEx.DriverList;

    if (entry == NULL)
    {
        DBGPRINT("crashdd:\tNo entries in DumpPointersEx driver list\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    while (entry != NULL)
    {
        //
        // There should always be only TWO drivers in this list - 
        // The normal i/o path port driver and miniport driver
        //
        if (i >= 2)
        {
            DBGPRINT("crashdd:\tToo many drivers in DumpPointersEx.DriverList\n");
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }

        //
        // The port driver is always first
        //
        if (i == 0)
        {
            //
            // If the caller already supplied the name, skip.
            //
            if (State->DumpPortDriver.Name.Buffer != NULL)
            {
                goto NextDumpDriver;
            }

            target = &State->DumpPortDriver.Name;
        }
        //
        // Miniport is second
        //
        else
        {
            //
            // If the caller already supplied the name, skip.
            //
            if (State->DumpMiniportDriver.Name.Buffer != NULL)
            {
                goto NextDumpDriver;
            }

            target = &State->DumpMiniportDriver.Name;
        }

        dumpDriver = (PDUMP_DRIVER)CONTAINING_RECORD(entry, DUMP_DRIVER, DumpDriverList);

        size = DUMP_DRIVER_NAME_LENGTH * sizeof(wchar_t);
        size += g_DumpPrefixLength * sizeof(wchar_t);
        target->Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool,
                                                        size,
                                                        CRASHDD_TAG);

        if (target->Buffer == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        target->MaximumLength = size;

        //
        // Prepend with "dump_"
        //
        RtlCopyMemory(target->Buffer, 
                      g_DumpPrefix,
                      g_DumpPrefixLength * sizeof(wchar_t));

        target->Length = g_DumpPrefixLength * sizeof(wchar_t);

        //
        // Tack on name
        //
        status = RtlAppendUnicodeToString(target, dumpDriver->DriverName);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("crashdd:\tFailed to build dump driver name :%08x\n", status);
            goto Exit;
        }

NextDumpDriver:
        entry = entry->Next;
        i++;
    }

    NT_ASSERT(State->DumpPortDriver.Name.Buffer != NULL);
    NT_ASSERT(State->DumpMiniportDriver.Name.Buffer != NULL);

    DBGPRINT("crashdd:\tAttempting to use dump drivers:\n");
    DBGPRINT("crashdd:\t\tdump port driver: %ws\n", State->DumpPortDriver.Name.Buffer);
    DBGPRINT("crashdd:\t\tdump miniport driver: %ws\n", State->DumpMiniportDriver.Name.Buffer);

    //
    // Store the entry points and base addresses of the dump drivers
    // for later use.
    //
    status = GetDumpDriverImageInfo(State);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tCould not locate dump driver image information: %08x\n",
                 status);
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:

    if (!NT_SUCCESS(status))
    {
        //
        // Reset image info
        //
        State->DumpMiniportDriver.BaseAddress = 0;
        State->DumpMiniportDriver.EntryPoint = NULL;
        State->DumpPortDriver.BaseAddress = 0;
        State->DumpPortDriver.EntryPoint = NULL;

        //
        // Free names
        //
        if (State->DumpPortDriver.Name.Buffer != NULL)
        {
            ExFreePoolWithTag(State->DumpPortDriver.Name.Buffer, CRASHDD_TAG);
            State->DumpPortDriver.Name.Buffer = NULL;
        }
        if (State->DumpMiniportDriver.Name.Buffer != NULL)
        {
            ExFreePoolWithTag(State->DumpMiniportDriver.Name.Buffer, CRASHDD_TAG);
            State->DumpMiniportDriver.Name.Buffer = NULL;
        }
    }

    return status;
}

///=========================================================================
/// GetDumpDriverImageInfo()
///
/// <summary>
/// Gets the base address and entry point for each of the dump port and 
/// miniport drivers whose names are stored in the state pointer.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetDumpDriverImageInfo (
    PCRASH_DUMP_STATE State
    )
{
    PLDR_DATA_TABLE_ENTRY entry;
    NTSTATUS status;

    NT_ASSERT(State != NULL);
    NT_ASSERT(State->PsLoadedModuleList != NULL);
    NT_ASSERT(State->DumpMiniportDriver.Name.Buffer != NULL);
    NT_ASSERT(State->DumpPortDriver.Name.Buffer != NULL);

    entry = State->PsLoadedModuleList;

    //
    // Locate entry points.
    //
    while (((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != 
            State->PsLoadedModuleList) && (entry != NULL))
    {
        if (entry->BaseDllName.Buffer == NULL)
        {
            entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
            continue;
        }

#if 0 // useful for debugging what dump drivers are loaded
        if (RtlCompareMemory(L"dump_", entry->BaseDllName.Buffer, 10) == 10)
        {
            __debugbreak();
        }
#endif
        if (RtlEqualUnicodeString(&entry->BaseDllName, 
                                  &State->DumpPortDriver.Name,
                                  TRUE))
        {
            State->DumpPortDriver.EntryPoint = (PDRIVER_INITIALIZE)entry->EntryPoint;
            State->DumpPortDriver.BaseAddress = (DWORD_PTR)entry->DllBase;
        }
        else if (RtlEqualUnicodeString(&entry->BaseDllName, 
                                        &State->DumpMiniportDriver.Name,
                                        TRUE))
        {
            State->DumpMiniportDriver.EntryPoint = (PDRIVER_INITIALIZE)entry->EntryPoint;
            State->DumpMiniportDriver.BaseAddress = (DWORD_PTR)entry->DllBase;
        }

        entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }

    if ((State->DumpPortDriver.BaseAddress == 0) || 
        (State->DumpPortDriver.EntryPoint == NULL))
    {
        DBGPRINT("crashdd:\tFailed to locate dump port driver base address or entry point\n");
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    if ((State->DumpMiniportDriver.BaseAddress == 0) || 
        (State->DumpMiniportDriver.EntryPoint == NULL))
    {
        DBGPRINT("crashdd:\tFailed to locate dump miniport driver base address or entry point\n");
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:

    return status;
}

///=========================================================================
/// GetDumpPortDriverName()
///
/// <summary>
/// Determines the name of the port driver and stores it in the state pointer.
/// </summary>
/// <returns>NT STATUS code</returns>
/// <remarks>
/// This function simply walks the loaded module list looking for a pre-determined
/// list of known dump port driver names.
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetDumpPortDriverName (
    __in PCRASH_DUMP_STATE State
    )
{
    PLDR_DATA_TABLE_ENTRY entry;
    USHORT size;
    USHORT baseSize;
    NTSTATUS status;
    USHORT compareLength17;
    USHORT compareLength16;
    USHORT compareLength5;

    NT_ASSERT(State != NULL);
    NT_ASSERT(State->PsLoadedModuleList != NULL);

    entry = State->PsLoadedModuleList;
    compareLength17 = 17 * sizeof(wchar_t);
    compareLength16 = 16 * sizeof(wchar_t);
    compareLength5 = 5 * sizeof(wchar_t);

    while (((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != 
            State->PsLoadedModuleList) && (entry != NULL))
    {
        if (entry->BaseDllName.Buffer == NULL)
        {
            goto NextDriver;
        }

        if (entry->BaseDllName.Length < compareLength5)
        {
            goto NextDriver;
        }

        //
        // All dump drivers are prefixed with "dump_"
        //
        if (RtlCompareMemory(entry->BaseDllName.Buffer,
                             L"dump_",
                             compareLength5) == compareLength5)
        {
            if (entry->BaseDllName.Length >= compareLength17)
            {
                //
                // SCSI/Storport
                //
                if ((RtlCompareMemory(entry->BaseDllName.Buffer,
                                      L"dump_scsiport.sys",
                                      compareLength17) == compareLength17) ||
                    (RtlCompareMemory(entry->BaseDllName.Buffer,
                                      L"dump_storport.sys",
                                      compareLength17) == compareLength17) ||
                    (RtlCompareMemory(entry->BaseDllName.Buffer,
                                      L"dump_diskdump.sys",
                                      compareLength17) == compareLength17))
                {
                    State->DiskDeviceInformation.IsScsiDevice = TRUE;
                    goto Done;
                }
            }
            else if (entry->BaseDllName.Length >= compareLength16)
            {
                //
                // ATA/IDE
                //
                if ((RtlCompareMemory(entry->BaseDllName.Buffer,
                                           L"dump_ataport.sys",
                                           compareLength16) == compareLength16) ||
                          (RtlCompareMemory(entry->BaseDllName.Buffer,
                                           L"dump_dumpata.sys",
                                           compareLength16) == compareLength16))
                {
                    State->DiskDeviceInformation.IsScsiDevice = FALSE;
                    goto Done;
                }
            }
            
            goto NextDriver;

            //
            // Store the port driver name in state pointer
            //
Done:
            baseSize = entry->BaseDllName.Length;
            size = baseSize + sizeof(wchar_t);
            State->DumpPortDriver.Name.MaximumLength = size;
            State->DumpPortDriver.Name.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool,
                                                                               size,
                                                                               CRASHDD_TAG);

            if (State->DumpPortDriver.Name.Buffer == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }

            RtlCopyMemory(State->DumpPortDriver.Name.Buffer,
                          entry->BaseDllName.Buffer,
                          baseSize);

            State->DumpPortDriver.Name.Length = baseSize;
            State->DumpPortDriver.Name.Buffer[baseSize / sizeof(WCHAR)] = L'\0';
            status = STATUS_SUCCESS;
            goto Exit;

        } // end check for "dump_" prefix
    
NextDriver:
        entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;

    } // end loop over modules

    status = STATUS_NOT_FOUND;

Exit:

    return status;
}

///=========================================================================
/// GetDumpMiniportDriverName()
///
/// <summary>
/// Determines the name of the miniport driver and stores it in the state pointer.
/// </summary>
/// <returns>NT STATUS code</returns>
/// <remarks>
/// This function uses the Disk device object to locate miniport name in normal
/// I/O path and then builds the name as "dump_[name].sys"
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetDumpMiniportDriverName (
    __in PCRASH_DUMP_STATE State
    )
{
    PDRIVER_OBJECT driverObject;
    PWCHAR offset;
    NTSTATUS status;
    DWORD_PTR wordEnd;
    USHORT size;

    NT_ASSERT(State != NULL);
    NT_ASSERT(State->DumpMiniportDriver.Name.Buffer == NULL);
    NT_ASSERT(State->DiskDeviceInformation.DeviceObject != NULL);

    //
    // Get the miniport base name from the normal I/O path
    // by referencing the disk device object.
    // Eg, \Driver\LSI_SAS, we need "LSI_SAS"
    //
    driverObject = State->DiskDeviceInformation.DeviceObject->DriverObject;

    NT_ASSERT(driverObject != NULL);
    NT_ASSERT(driverObject->DriverName.Buffer != NULL);

    offset = wcsrchr(driverObject->DriverName.Buffer, L'\\');
       
    if (offset == NULL)
    {
        DBGPRINT("crashdd:\tFailed to parse miniport driver name in disk device object\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    offset++;
    wordEnd = ((DWORD_PTR)driverObject->DriverName.Buffer) + driverObject->DriverName.Length;

    NT_ASSERT((DWORD_PTR)offset < wordEnd);

    //
    // Actual size to allocate is the miniport name length
    // plus the "dump_" prefix plus a null-term.
    //
    size = (USHORT)(wordEnd - (DWORD_PTR)offset); //actual file name length
    size += g_DumpPrefixLength * sizeof(wchar_t); //"dump_" prefix
    size += 4 * sizeof(wchar_t); // ".sys"
    size += sizeof(wchar_t); //null term

    //
    // Allocate space for the target string in our State pointer
    //
    State->DumpMiniportDriver.Name.MaximumLength = size;
    State->DumpMiniportDriver.Name.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool,
                                                                           size,
                                                                           CRASHDD_TAG);

    if (State->DumpMiniportDriver.Name.Buffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Prepend with "dump_"
    //
    RtlCopyMemory(State->DumpMiniportDriver.Name.Buffer,
                  g_DumpPrefix,
                  g_DumpPrefixLength * sizeof(wchar_t));

    State->DumpMiniportDriver.Name.Length = g_DumpPrefixLength * sizeof(wchar_t);

    //
    // Tack on miniport name
    //
    status = RtlAppendUnicodeToString(&State->DumpMiniportDriver.Name, offset);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to build miniport driver name :%08x\n", status);
        goto Exit;
    }

    //
    // Tack on .sys
    //
    status = RtlAppendUnicodeToString(&State->DumpMiniportDriver.Name, L".sys");

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to build miniport driver name :%08x\n", status);
        goto Exit;
    }

Exit:

    return status;
}

///=========================================================================
/// CrashDumpStackRead()
///
/// <summary>
/// Uses the crash dump stack to read from a disk device.
/// </summary>
/// <returns>NT STATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS 
CrashDumpStackRead (
    __in PCRASHDD_EXTENSION Extension
    )
{
    NTSTATUS status;
    NTSTATUS status2;
    CRASH_DUMP_STATE crashDumpState;
    ULONG i;
    ULONG_PTR memoryBlock;
    BOOLEAN patched;
    IPI_CALL_ARGUMENT ipiArgument;

    NT_ASSERT(Extension != NULL);

    patched = FALSE;

    DBGPRINT("crashdd:  Initializing crash dump state...\n");

    //
    // Initialize crash dump state
    //
    status = InitializeCrashDumpState(Extension,
                                      &crashDumpState);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tCould not initialize crash dump state:  %08x\n", status);
        goto Exit;
    }

    DBGPRINT("crashdd:  Retrieving disk device information...\n");

    //
    // Get disk device information
    //
    status = GetDiskDeviceInformation(Extension, &crashDumpState);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to get disk device information: %08x\n", status);
        goto Exit;
    }

    DBGPRINT("crashdd:  Locating crash dump drivers in memory...\n");

    //
    // Locate dump port and miniport drivers
    //
    // TODO:  validate that the drivers we found really are the dump port/miniport drivers
    // by parsing their text sections looking for recognizable function names or patterns.
    //
    status = LocateCrashDumpDrivers(&crashDumpState);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tCould not locate crash dump drivers:  %08x\n", status);
        goto Exit;
    }

    NT_VERIFY(crashDumpState.DumpPortDriver.BaseAddress != 0);
    NT_VERIFY(crashDumpState.DumpPortDriver.EntryPoint != NULL);
    NT_VERIFY(crashDumpState.DumpMiniportDriver.BaseAddress != 0);
    NT_VERIFY(crashDumpState.DumpMiniportDriver.EntryPoint != NULL);

    //
    // Locate the address of the dump port driver's internal device extension structure.
    // On all platforms and transports, the DriverEntry of the dump port driver sets
    // its device extension pointer equal to the pointer at DumpInit.MemoryBlock + 0x10 or 0x18.
    // We control that structure, so set the pointer manually.
    //
    memoryBlock = (ULONG_PTR)crashDumpState.DumpInit->DumpStack.Init.MemoryBlock;

    if (Extension->Is64bit != FALSE)
    {
        crashDumpState.DumpPortDriver.Extension = memoryBlock + DISKDUMP_DEVEXT_OFFSET_64;
    }
    else
    {
        crashDumpState.DumpPortDriver.Extension = memoryBlock + DISKDUMP_DEVEXT_OFFSET_32;
    }

    if (crashDumpState.DumpPortDriver.Extension < 0x80000000)
    {
        DBGPRINT("crashdd:  Invalid dump port device extension pointer %p!\n", 
                 crashDumpState.DumpPortDriver.Extension);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    DBGPRINT("crashdd:  Located dump port device extension pointer at %p.\n",
            crashDumpState.DumpPortDriver.Extension);

    //
    // Now invoke the dump port driver's initialization routine to initialize itself.
    // Among other reasons, this call is important because it sets the device extension
    // pointer we just assigned above.

    //
    // NB: In Windows 8, we must first patch DriverEntry because it has a call to
    // MarkHiberDiskPhase() which calls PoSetHiberRange().  This call relies on
    // the system being in a hiber state, which we can't force.
    //
    if (Extension->OperatingSystem == Win8)
    {
        //
        // TODO:  Add IDE support
        // Note: We cannot check this in our driverEntry, so this is our first
        // opportunity to validate IDE compatibility on Win8.
        //
        if (crashDumpState.DiskDeviceInformation.IsScsiDevice == FALSE)
        {
            status = STATUS_NOT_SUPPORTED;
            DBGPRINT("crashdd:  IDE transport not supported on Windows 8.\n");
            goto Exit;
        }
        
        DBGPRINT("crashdd:  Patching dump port driver...\n");

        status = PatchDumpPortDriver(&crashDumpState, Extension->Is64bit, TRUE);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("crashdd:\tFailed to patch dump port driver: %08x\n", status);
            goto Exit;
        }

        patched = TRUE;
    }

    //
    // Call dump port and miniport driver entry points
    //
    DBGPRINT("crashdd:  Calling dump port and miniport driver entry points...\n");

    ipiArgument.Barrier = 1;
    ipiArgument.Callback = IpiBroadcastCallDumpDriverEntryPoints;
    ipiArgument.Context = &crashDumpState;

    status = (NTSTATUS)KeIpiGenericCall(CallIpiBroadcastFunction, 
                                        (ULONG_PTR)&ipiArgument);
    
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to call dump driver entry point: %08x\n", status);
        goto Exit;
    }
        
    //
    // Process SCSI request.
    //
    if (crashDumpState.DiskDeviceInformation.IsScsiDevice != FALSE)
    {
        DBGPRINT("crashdd:  Beginning SCSI operation...\n");

        status = CrashScsiRead(Extension, 
                               &crashDumpState);
    }
    //
    // Process IDE request.
    //
    else
    {
        DBGPRINT("crashdd:  Beginning IDE operation...\n");

        //
        // Not supported on win8 yet
        //
        if (Extension->OperatingSystem == Win8)
        {
            DBGPRINT("crashdd:\tIDE drives are not supported.\n");
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }

        status = CrashIdeRead(Extension, 
                              &crashDumpState);
    }

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tOperation failed with status %08x\n", status);
        goto Exit;
    }
      
#if DBG

    if (Extension->UserRequest->BytesRead == 512)
    {
        NT_ASSERT(Extension->UserRequest->OutputBuffer != NULL);

        DBGPRINT("crashdd:\tData read:\n\t\t");

        for (i = 0; i < Extension->UserRequest->Size; i++)
        {
            DBGPRINT("%02x",((PUCHAR)Extension->UserRequest->OutputBuffer)[i]);
            if ((i != 0) && ((i % 32) == 0))
            {
                DBGPRINT("\n\t\t");
            }
        }

        DBGPRINT("\n");
    }

#endif
  

Exit:

    DBGPRINT("crashdd:  Releasing resources...\n");
    FreeCrashDumpState(&crashDumpState);

    //
    // Unpatch the dump port driver
    //
    if (patched != FALSE)
    {
        DBGPRINT("crashdd:  Unpatching dump port driver...\n");

        status2 = PatchDumpPortDriver(&crashDumpState, Extension->Is64bit, FALSE);

        if (!NT_SUCCESS(status2))
        {
            DBGPRINT("crashdd:\tFailed to unpatch dump port driver: %08x\n", status2);
            status = status2;
        }
    }

    DBGPRINT("crashdd:  Complete\n");

    return status;
}

///=========================================================================
/// <summary>
/// Windows 8 specific function that patches the dump port driver's DriverEntry
/// routine - method differs from x86 to x64.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
PatchDumpPortDriver (
    __in PCRASH_DUMP_STATE State,
    __in BOOLEAN Is64bit,
    __in BOOLEAN Patch
    )
{
    NTSTATUS status;
    UCHAR patch = 0x90;
    ULONG i;
    ULONG_PTR virtualAddress;
    PVOID systemAddress;
    PMDL mdl;

    NT_ASSERT(State != NULL);
    NT_ASSERT(State->DumpPortDriver.BaseAddress != 0);

    mdl = NULL;

    //
    // Patch over original value
    //
    if (Patch != FALSE)
    {
        NT_ASSERT(State->DumpPortDriver.PatchMdl == NULL);

        //
        // 64-bit, patch import table so PoSetHiberRange() points
        // to our own no-op function
        //
        if (Is64bit != FALSE)
        {
            status = GetImportAddressEntry64(State->DumpPortDriver.BaseAddress, 
                                             "ntoskrnl.exe",
                                             "PoSetHiberRange",
                                             (PVOID*)&virtualAddress);

            if (!NT_SUCCESS(status))
            {
                DBGPRINT("crashdd:\tFailed to locate dump port driver location to patch: %08x\n",
                         status);
                goto Exit;
            }

            NT_ASSERT(virtualAddress != 0);

            status = PrepareForPatch((PVOID)virtualAddress,
                                     sizeof(ULONGLONG),
                                     &mdl,
                                     &systemAddress);

            if (!NT_SUCCESS(status))
            {
                DBGPRINT("crashdd:\tFailed to prepare MDL for patching: %08x\n", status);
                goto Exit;
            }

            NT_ASSERT(systemAddress != NULL);
            NT_ASSERT(mdl != NULL);

            State->DumpPortDriver.PatchOriginalImport = *(PULONGLONG)systemAddress;
            *(PULONGLONG)systemAddress = (ULONGLONG)DummyPoSetHiberRange;

            DBGPRINT("crashdd:\tPatched import address %p to %I64x\n", 
                     systemAddress,
                     *(PULONGLONG)systemAddress);

        }
        //
        // 32-bit, patch a single call to internal MarkHiberBootPhase()
        // inside DriverEntry()
        //
        else
        {
            //
            // Scan text section for address to patch
            //
            status = ScanDriverSection(".text",
                                       5,
                                       State->DumpPortDriver.BaseAddress, 
                                       DISKDUMP_PATCH_BYTES_MAGIC_32, 
                                       0,
                                       &virtualAddress);

            if (!NT_SUCCESS(status))
            {
                DBGPRINT("crashdd:\tFailed to locate dump port driver location to patch: %08x\n",
                         status);
                goto Exit;
            }

            NT_ASSERT(virtualAddress != 0);

            status = PrepareForPatch((PVOID)virtualAddress,
                                     DISKDUMP_PATCH_BYTES_LENGTH_32,
                                     &mdl,
                                     &systemAddress);

            if (!NT_SUCCESS(status))
            {
                DBGPRINT("crashdd:\tFailed to prepare MDL for patching: %08x\n", status);
                goto Exit;
            }

            NT_ASSERT(systemAddress != NULL);
            NT_ASSERT(mdl != NULL);

            //
            // Patch
            //
            for (i = 0; i < DISKDUMP_PATCH_BYTES_LENGTH_32; i++)
            {
                State->DumpPortDriver.PatchOriginalBytes[i] = 
                        *((PUCHAR)((ULONG_PTR)systemAddress+i));

                *((PUCHAR)((ULONG_PTR)systemAddress+i)) = patch;
            }

            DBGPRINT("crashdd:\tPatched address %p with %lu bytes\n", 
                     systemAddress,
                     DISKDUMP_PATCH_BYTES_LENGTH_32);

        } //end 64-bit check

        //  
        // Save MDL for next time.
        //
        State->DumpPortDriver.PatchMdl = mdl;
    }
    //
    // Patch the original value back
    //
    else
    {
        mdl = State->DumpPortDriver.PatchMdl;

        NT_ASSERT(mdl != NULL);

        //
        // Get system address to modify the mapped memory
        //
        systemAddress = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);

        if (systemAddress == NULL)
        {
            DBGPRINT("crashdd:\tCould not get a system address for mapped address\n");
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }

        if (Is64bit != FALSE)
        {
            *(PULONGLONG)systemAddress = State->DumpPortDriver.PatchOriginalImport;
        }
        else
        {
            for (i = 0; i < DISKDUMP_PATCH_BYTES_LENGTH_32; i++)
            {
                NT_ASSERT(*((PUCHAR)((ULONG_PTR)systemAddress+i)) == 0x90);

                *((PUCHAR)((ULONG_PTR)systemAddress+i)) = 
                    State->DumpPortDriver.PatchOriginalBytes[i];
            }
        }
    }

    status = STATUS_SUCCESS;

Exit:

    //
    // Free MDL resources on failure or when we are unpatching
    //
    if (!NT_SUCCESS(status) || Patch == FALSE)
    {
        //
        // Unlock and free the mdl
        //
        if (mdl != NULL)
        {
            __try
            {
                MmUnlockPages(mdl);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DBGPRINT("crashdd:\tAn exception occured attempting to unlock the mdl %p\n", 
                         mdl);
            }
        
            IoFreeMdl(mdl);
        }
    }

    return status;
}

///=========================================================================
/// <summary>
/// Calls the driver entry point for both the dump port and miniport drivers.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// This function must be called from the IPI broadcast routine, which 
/// insures that it runs only on a single processor.  Other crash dump
/// environment restrictions must be in effect before calling this function.
/// </remarks>
///========================================================================= 
ULONG_PTR
IpiBroadcastCallDumpDriverEntryPoints (
    __in ULONG_PTR Argument
    )
{
    NTSTATUS status;
    PCRASH_DUMP_STATE state;

    state = (PCRASH_DUMP_STATE)Argument;

    NT_ASSERT(state != NULL);
    NT_ASSERT(state->DumpInit != NULL);
    NT_ASSERT(state->DumpPortDriver.EntryPoint != NULL);
    NT_ASSERT(state->DumpMiniportDriver.EntryPoint != NULL);

    status = state->DumpPortDriver.EntryPoint(NULL, (PUNICODE_STRING)state->DumpInit);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = state->DumpMiniportDriver.EntryPoint(NULL, NULL);

    if (!NT_SUCCESS(status))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

Exit:

    return (ULONG_PTR)status;
}

///=========================================================================
/// <summary>
/// This is a dummy function used when patching the dump port driver's IAT
/// entry for nt!PoSetHiberRange when using windows 8 x64.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
VOID
NTAPI
DummyPoSetHiberRange (
    IN PVOID HiberContext,
    IN ULONG Flags,
    IN OUT PVOID StartPage,
    IN ULONG Length,
    IN ULONG PageTag 
    )
{
    DBG_UNREFERENCED_PARAMETER(HiberContext);
    DBG_UNREFERENCED_PARAMETER(Flags);
    DBG_UNREFERENCED_PARAMETER(StartPage);
    DBG_UNREFERENCED_PARAMETER(Length);
    DBG_UNREFERENCED_PARAMETER(PageTag);

    return;
}