
#include "CrashDumpScsi.hpp"

///=========================================================================
/// CrashScsiRead()
///
/// <summary>
/// Communicates with a SCSI crash dump stack to read data off a disk device.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
CrashScsiRead (
    __in PCRASHDD_EXTENSION Extension,
    __in PCRASH_DUMP_STATE State
    )
{
    PMDL userMdl;
    NTSTATUS status;
    NTSTATUS status2;
    LARGE_INTEGER offset;
    BOOLEAN normalPathDisabled;
    SCSI_REQUEST_BLOCK srb;
    SCSI_IPI_REQUEST ipiRequest;
    IPI_CALL_ARGUMENT ipiArgument;
    DISK_DUMP_IO_ISSUE_ARGUMENTS ioIssueArguments;
    PVOID outputBuffer;
    ULONG outputBufferLength;
    PMDL partialMdl;
    PVOID virtualAddress;
    ULONG length;
    ULONG consumed;
    ULONG_PTR mdlOffset;

    NT_ASSERT(Extension != NULL);
    NT_ASSERT(State != NULL);

    normalPathDisabled = FALSE;
    srb.DataBuffer = NULL;  
    userMdl = NULL;
    outputBuffer = NULL;
    Extension->UserRequest->BytesRead = 0;
    partialMdl = NULL;

    //  
    // Get user-supplied values (basic validation done in DriverMain.cpp)
    //
    outputBufferLength = Extension->UserRequest->Size;
    status = GetUserBuffer(Extension->UserRequest->OutputBuffer,
                           outputBufferLength,
                           &userMdl,
                           &outputBuffer,
                           TRUE);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to get user buffer\n");
        goto Exit;
    }

    NT_ASSERT(outputBuffer != NULL);
    NT_ASSERT(userMdl != NULL);

    DBGPRINT("crashdd:\tSearching for appropriate I/O function...\n");

    //
    // Locate the internal function in the SCSI dump port driver responsible
    // for issuing I/O to the dump miniport.
    //
    status = CrashScsiGetIoFunction(Extension, State);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to locate function\n");
        goto Exit;
    }
    
    DBGPRINT("crashdd:\tDisabling the normal I/O path...\n");

    //
    // Disable normal I/O path
    //
    // Before we trash any I/O in progress (any SRB inserted in the middle
    // of a pending I/O request would trash the device register state) on 
    // the normal I/O path by using the same hardware beneath the crash dump I/O path, 
    // flush and lock the internal SCSIPort queue
    //
    // Ref:  http://msdn.microsoft.com/en-us/library/windows/hardware/ff561597(v=vs.85).aspx
    //
    status = ToggleNormalIoPath(State->DiskDeviceInformation.DeviceObject, FALSE);
                                    
    if (!NT_SUCCESS(status))
    {
        DBGPRINT("\ncrashdd:\tCould not disable normal I/O path:  %08x\n", status);
        goto Exit;
    }

    ipiRequest.OperatingSystem = Extension->OperatingSystem;
    normalPathDisabled = TRUE;
    consumed = 0;

    //
    // Allocate an mdl to be used when splitting up request.
    // It needs to be large enough for a single request.        
    //
    partialMdl = IoAllocateMdl(MmGetMdlVirtualAddress(userMdl), 
                               IO_DUMP_COMMON_BUFFER_SIZE,
                               FALSE, 
                               FALSE,
                               NULL);

    if (partialMdl == NULL)
    {
        DBGPRINT("crashdd:\tFailed to allocate partial MDL of size %lu\n",
                 IO_DUMP_COMMON_BUFFER_SIZE);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    DBGPRINT("crashdd:\tSending I/O request...\n");

    //
    // In Win8, since we don't prepare and send an SRB directly to StartIo, 
    // we must force it to use 16-byte CDB by manually setting this field
    // in the dump port driver's device extension.
    //
    if (Extension->OperatingSystem == Win8)
    {
        (*(PCHAR)(State->DumpPortDriver.Extension + 0x25B)) = 1;
    }

    //
    // Transmit request.
    // Break up requests into partial MDL's.
    // Note: diskdump does not support MDL chaining
    // so we have to make a call for each MDL..
    //
    offset.QuadPart = Extension->UserRequest->Offset;

    while (consumed < outputBufferLength)
    {
        length = IO_DUMP_COMMON_BUFFER_SIZE;

        if ((consumed + length) > outputBufferLength)
        {
            length = outputBufferLength - consumed;
        }

        virtualAddress = (PVOID)((ULONG_PTR)MmGetMdlVirtualAddress(userMdl) + consumed);

        //
        // Create a partial MDL to hold the amount of data for this iteration.
        //
        IoBuildPartialMdl(userMdl, partialMdl, virtualAddress, length);

        //
        // This creates the Pfn array mapping just beyond the MDL
        // structure which is required for DMA use.
        //
        MmBuildMdlForNonPagedPool(partialMdl);

        //
        // In Windows 8, it's not necessary to build our own read SRB.  We
        // just map an MDL that describes our read request.  DiskDumpIoIssue
        // wraps our request in an SRB for us.
        //
        if (Extension->OperatingSystem == Win8)
        {
            ioIssueArguments.Action = 0;
            ioIssueArguments.Mdl = partialMdl;
            ioIssueArguments.Offset = &offset;
            ioIssueArguments.ScsiOp = SCSIOP_READ;
            ipiRequest.Function = (PVOID)State->DumpPortDriver.IoFunctionPointer;
            ipiRequest.u.IoIssueArguments = &ioIssueArguments;
        }
        //
        // Prior to Windows 8, we have to build an explicit SRB that describes
        // the I/O request.  The SRB is the parameter to StartIo.  The MDL still
        // maps to the user buffer but a pointer to that buffer is stored in
        // SRB.DataBuffer which StartIo populates.
        //
        else
        {
            //
            // Store pointer to the MDL in dump driver extension
            //
            mdlOffset = State->DumpPortDriver.Extension;

            #ifdef _AMD64_
                mdlOffset += DISKDUMP_DEVEXT_MDL_OFFSET_64;
            #else
                mdlOffset += DISKDUMP_DEVEXT_MDL_OFFSET_32;
            #endif

            if (consumed == 0)
            {
                DBGPRINT("crashdd:\tStoring pointer to MDL at dump extension address %p!\n", 
                         mdlOffset);
            }

            //
            // Stuff it into the port driver's device extension
            //
            *(ULONG_PTR*)mdlOffset = (ULONG_PTR)(partialMdl);

            //
            // Build an SRB around that partial buffer.
            //
            CrashScsiBuildReadSrb(State, &srb, partialMdl->MappedSystemVa, offset.QuadPart, length);

            ipiRequest.Function = (PVOID)State->DumpPortDriver.IoFunctionPointer;
            ipiRequest.u.Srb = &srb;
        }

        //
        // Transmit the SRB using IPI interface
        // 
        DBGPRINT("crashdd:\t\t%p <= bytes %lu to %lu...\n", 
                 virtualAddress, 
                 consumed, 
                 consumed + length);

        ipiArgument.Barrier = 1;
        ipiArgument.Context = &ipiRequest;
        ipiArgument.Callback = CrashScsiIpiBroadcastSendIoRequest;

        status = (NTSTATUS)KeIpiGenericCall(CallIpiBroadcastFunction, 
                                            (ULONG_PTR)&ipiArgument);
        if (!NT_SUCCESS(status))
        {
            DBGPRINT("crashdd:\tRequest of length %lu failed with status %08x\n",
                     length,
                     status);
            goto Exit;
        }

        MmPrepareMdlForReuse(partialMdl);
        consumed += length;
        offset.QuadPart += length;
    }

    DBGPRINT("crashdd:\tSuccess!\n");

    Extension->UserRequest->BytesRead = outputBufferLength;

Exit:

    DBGPRINT("crashdd:\tEnabling the normal I/O path...\n");

    //
    // Re-enable the normal I/O path by unlocking the scsiport queue
    //
    if (normalPathDisabled != FALSE)
    {
        status2 = ToggleNormalIoPath(State->DiskDeviceInformation.DeviceObject, TRUE);

        if (!NT_SUCCESS(status2))
        {
            DBGPRINT("\ncrashdd:\tCould not re-enable normal I/O path:  %08x\n", status2);
            status = status2;
        }
    }

    if (userMdl != NULL)
    {
        __try
        {
             MmUnlockPages(userMdl);
        }
        __except(EXCEPTION_CONTINUE_EXECUTION)
        {
            DBGPRINT("\ncrashdd:\tCaught exception trying to unlock user address %p\n",
                     userMdl->StartVa);
        }

        IoFreeMdl(userMdl);
    }

    if (partialMdl != NULL)
    {
        IoFreeMdl(partialMdl);
    }

    return status;
}

///=========================================================================
/// CrashScsiGetIoFunction()
///
/// <summary>
/// Locates the function in the dump port driver responsible for completing
/// a single, synchronous I/O request.  This function varies per OS, bitness,
/// and transport type.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
CrashScsiGetIoFunction (
    PCRASHDD_EXTENSION Extension,
    PCRASH_DUMP_STATE State
    )
{
    NTSTATUS status;
    UNICODE_STRING name;

    NT_ASSERT(Extension != NULL);
    NT_ASSERT(State != NULL);
    NT_ASSERT(State->DumpPortDriver.BaseAddress > 0);

    //
    // For all versions of Windows prior to Windows 8, we find StartIo.
    //
    if (Extension->OperatingSystem != Win8)
    {
        #ifndef _AMD64_
        status = ScanDriverSection(".text",
                                    5,
                                    State->DumpPortDriver.BaseAddress, 
                                    DISKDUMP_STARTIO_MAGIC_32, 
                                    DISKDUMP_STARTIO_DISTANCE_UP_32,
                                    &State->DumpPortDriver.IoFunctionPointer);
        #else
        status = ScanDriverSection(".text",
                                    5,
                                    State->DumpPortDriver.BaseAddress, 
                                    DISKDUMP_STARTIO_MAGIC_64, 
                                    DISKDUMP_STARTIO_DISTANCE_UP_64,
                                    &State->DumpPortDriver.IoFunctionPointer);
        #endif

        RtlInitUnicodeString(&name, L"StartIo");
    }
    else
    {
        //
        // In Windows 8, we use DiskDumpIoIssue(), which handles calling
        // StartIo for us.
        //
        #ifndef _AMD64_
        status = ScanDriverSection(".text",
                                   5,
                                   State->DumpPortDriver.BaseAddress, 
                                   DISKDUMP_IOISSUE_MAGIC_32, 
                                   DISKDUMP_IOISSUE_DISTANCE_UP_32,
                                   &State->DumpPortDriver.IoFunctionPointer);
        #else
        status = ScanDriverSection(".text",
                                   5,
                                   State->DumpPortDriver.BaseAddress, 
                                   DISKDUMP_IOISSUE_MAGIC_64, 
                                   DISKDUMP_IOISSUE_DISTANCE_UP_64,
                                   &State->DumpPortDriver.IoFunctionPointer);
        #endif

        RtlInitUnicodeString(&name, L"DiskDumpIoIssue");
    }

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tI/O function %ws could not be located: %08x\n", 
                name.Buffer, 
                status);
        goto Exit;
    }

    NT_ASSERT(State->DumpPortDriver.IoFunctionPointer != 0);
    status = STATUS_SUCCESS;
    DBGPRINT("crashdd:\tSCSI I/O function %ws found at address %p.\n", 
             name.Buffer,
             State->DumpPortDriver.IoFunctionPointer);

Exit:

    return status;
}

///=========================================================================
/// CrashScsiBuildReadSrb()
///
/// <summary>
/// Sets up a SCSI_REQUEST_BLOCK to read data from the disk drive.  This 
/// function sets the Srb.DataBuffer pointer equal to the passed-in buffer,
/// which must be a system address returned from MmGetSystemAddressForMdlSafe,
/// after creating an MDL to describe the underlying user request buffer.
/// </summary>
/// <returns>nothing</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
VOID
CrashScsiBuildReadSrb (
    __in PCRASH_DUMP_STATE State,
    __inout PSCSI_REQUEST_BLOCK Srb,
    __in PVOID Buffer,
    __in ULONGLONG Offset,
    __in ULONG Size
    )
{
    ULONG bytesPerSector;
    ULONGLONG lba;
    ULONG lbaHigh;
    ULONG lbaLow;
    ULONG blocks;

    NT_ASSERT(State != NULL);
    NT_ASSERT(Srb != NULL);
    NT_ASSERT(Size > 0);
    NT_ASSERT(Buffer != NULL);

    //
    // Prepare SRB
    //
    RtlZeroMemory(Srb, sizeof(SCSI_REQUEST_BLOCK));

    Srb->Length = sizeof(SCSI_REQUEST_BLOCK);
    Srb->Function = SRB_FUNCTION_EXECUTE_SCSI;
    Srb->PathId = State->DumpInit->DumpStack.Init.TargetAddress->PathId;
    Srb->TargetId = State->DumpInit->DumpStack.Init.TargetAddress->TargetId;
    Srb->Lun = State->DumpInit->DumpStack.Init.TargetAddress->Lun;

    //
    // Notes on flags:
    // -"data in" means SYSTEM <-- DEVICE (we are copying data FROM disk to buffer in memory)
    // - all these flags are used in crash dump write CDB (replace SRB_FLAGS_DATA_IN with _OUT)
    //
    Srb->SrbFlags = SRB_FLAGS_DATA_IN | SRB_FLAGS_DISABLE_AUTOSENSE | 
                    SRB_FLAGS_DISABLE_DISCONNECT | SRB_FLAGS_DISABLE_SYNCH_TRANSFER;
    Srb->SenseInfoBufferLength = 0;
    Srb->DataTransferLength = Size;
    Srb->SenseInfoBuffer = NULL;
    Srb->TimeOutValue = 10;
    Srb->SrbExtension = NULL;
    Srb->DataBuffer = Buffer;
    bytesPerSector = State->DiskDeviceInformation.DiskGeometry.Geometry.BytesPerSector;

    NT_ASSERT(bytesPerSector > 0);

    lba = Offset / bytesPerSector;
    lbaHigh = HIDWORD(lba);
    lbaLow = LODWORD(lba);
    blocks = Size / bytesPerSector;

    //
    // The SCSI-2 16-byte CDB (command descriptor block).
    // We use the 16-byte version of the read instruction 
    // vice 10-byte version to support 64-bit LBA's.
    //

    /*
    Srb->CdbLength = 0xa;
	Srb->Cdb[0] = SCSIOP_READ; //operation
    Srb->Cdb[1] = 0;			  //LUN-DPO-FUA-Reserved-RelAddr
	Srb->Cdb[2] = 0;			  //LBA (MSB)
	Srb->Cdb[3] = 0;			  //..
	Srb->Cdb[4] = 0;			  //..
	Srb->Cdb[5] = 0;			  //LBA (LSB)
	Srb->Cdb[6] = 0;			  //reserved
    Srb->Cdb[7] = 0;			  //MSB transfer length (number of blocks, assuming 1 block = 512 bytes)
    Srb->Cdb[8] = 1;			  //LSB transfer length
	Srb->Cdb[9] = 0;			  //control byte
    */

    
    Srb->CdbLength = 0x10;
    Srb->Cdb[0] = SCSIOP_READ16;                   // operation
    Srb->Cdb[1] = 0;                               // LUN-DPO-FUA-Reserved-RelAddr
    Srb->Cdb[2] = HIBYTE(HIWORD(lbaHigh));        // LBA (MSB)
    Srb->Cdb[3] = LOBYTE(HIWORD(lbaHigh));        // ..
    Srb->Cdb[4] = HIBYTE(LOWORD(lbaHigh));        // ..
    Srb->Cdb[5] = LOBYTE(LOWORD(lbaHigh));        // ..
    Srb->Cdb[6] = HIBYTE(HIWORD(lbaLow));         // ..
    Srb->Cdb[7] = LOBYTE(HIWORD(lbaLow));         // ..
    Srb->Cdb[8] = HIBYTE(LOWORD(lbaLow));         // ..
    Srb->Cdb[9] = LOBYTE(LOWORD(lbaLow));         // LBA (LSB)
    Srb->Cdb[10] = 0;                              // reserved
    Srb->Cdb[11] = HIBYTE(HIWORD(blocks));        // Tfer length in blocks (MSB)
    Srb->Cdb[12] = LOBYTE(HIWORD(blocks));        // ..
    Srb->Cdb[13] = HIBYTE(LOWORD(blocks));        // ..
    Srb->Cdb[14] = LOBYTE(LOWORD(blocks));        // Tfer length (LSB)
    Srb->Cdb[15] = 0;                              // control byte

    

    return;
}

///=========================================================================
/// CrashScsiIpiBroadcastSendIoRequest()
/// <summary>
/// Transmits the SCSI I/O request.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// This function must be called from the IPI broadcast routine, which 
/// insures that it runs only on a single processor.  Other crash dump
/// environment restrictions must be in effect before calling this function.
/// </remarks>
///========================================================================= 
ULONG_PTR
CrashScsiIpiBroadcastSendIoRequest (
    __in ULONG_PTR Argument
    )
{
    NTSTATUS status;
    PSCSI_IPI_REQUEST request;

    request = (PSCSI_IPI_REQUEST)Argument;

    NT_ASSERT(request != NULL);
    NT_ASSERT(request->Function != NULL);
    NT_ASSERT((request->u.IoIssueArguments != NULL) || (request->u.Srb != NULL));

    //
    // Call appropriate I/O function
    //
    if (request->OperatingSystem == Win8)
    {
        #ifdef _WIN64
        status = DiskDumpIoIssueProxyCall64(request->Function,
                                            request->u.IoIssueArguments->Action,
                                            request->u.IoIssueArguments->ScsiOp,
                                            request->u.IoIssueArguments->Offset,
                                            request->u.IoIssueArguments->Mdl);
        #else
        status = DiskDumpIoIssueProxyCall32(request->Function,
                                            request->u.IoIssueArguments->Action,
                                            request->u.IoIssueArguments->ScsiOp,
                                            request->u.IoIssueArguments->Offset,
                                            request->u.IoIssueArguments->Mdl);
        #endif
    }
    else
    {
        #ifndef _AMD64_
        status = StartIoProxyCall32(request->Function, request->u.Srb);
        #else
        status = StartIoProxyCall64(request->Function, request->u.Srb);
        #endif
    }

    return (ULONG_PTR)status;
}