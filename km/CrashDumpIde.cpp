
#include "CrashDumpIde.hpp"

// 
// Used for IPI call barrier
//
static volatile UCHAR g_CpuBarrier;
static volatile LONG g_CpuNumber;

///=========================================================================
/// CrashIdeRead()
///
/// <summary>
/// Communicates with an IDE crash dump stack.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// This code has not been verified to work (experimental).
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
CrashIdeRead (
    __in PCRASHDD_EXTENSION Extension,
    __in PCRASH_DUMP_STATE State
    )
{
    ULONG_PTR crb;
    NTSTATUS status;
    IDE_REQUEST_BLOCK irb;
    BOOLEAN normalPathDisabled;
    IDE_IPI_REQUEST ipiRequest;
    ULONG_PTR dumpIdeWaitOnRequest;
    IPI_CALL_ARGUMENT ipiArgument;

    //  
    // BUG:  This variable must be filled with bytes actually read
    //
    Extension->UserRequest->BytesRead = 0;

    NT_ASSERT(Extension != NULL);
    NT_ASSERT(State != NULL);
    NT_ASSERT(State->DumpPortDriver.BaseAddress > 0);
    NT_ASSERT(Extension->UserRequest->OutputBuffer != NULL);
    NT_ASSERT(Extension->UserRequest->Size != 0);
    NT_ASSERT(Extension->UserRequest->Size <= MAX_READ_SIZE);

    //
    // TODO:  IDE was experimental at best pre-win7
    // and no support for win8.
    // Need to revisit.
    //
    NT_ASSERT(FALSE);

    irb.DataBuffer = NULL;
    normalPathDisabled = FALSE;
    RtlZeroMemory(&ipiRequest, sizeof(ipiRequest));

    //
    // TODO:  Support Win8
    //
    NT_VERIFY(Extension->OperatingSystem != Win8);

    DBGPRINT("crashdd:\tSearching for appropriate I/O function...\n");

    //
    // Locate the internal function in the IDE dump port driver responsible
    // for issuing I/O to the dump miniport.
    //
    status = CrashIdeGetIoFunction(Extension, State);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to locate function\n");
        goto Exit;
    }

    //
    // Need dump port's IdeDumpWaitOnRequest to poll for a result.
    //
#ifndef _AMD64_
    status = ScanDriverSection(".text",
                               5,
                               State->DumpPortDriver.BaseAddress,
                               DUMPATA_IDEDUMPWAITONREQUEST_MAGIC_32, 
                               DUMPATA_IDEDUMPWAITONREQUEST_DISTANCE_UP_32,
                               (PULONG_PTR)&dumpIdeWaitOnRequest);
#else
    status = ScanDriverSection(".text",
                               5,
                               State->DumpPortDriver.BaseAddress,
                               DUMPATA_IDEDUMPWAITONREQUEST_MAGIC_64, 
                               DUMPATA_IDEDUMPWAITONREQUEST_DISTANCE_UP_64,
                               (PULONG_PTR)&dumpIdeWaitOnRequest);
#endif

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tIdeDumpWaitOnRequest could not be located: %08x\n", status);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    NT_ASSERT(dumpIdeWaitOnRequest != NULL);

    DBGPRINT("crashdd:\tIdeDumpWaitOnRequest found at address %p.\n", dumpIdeWaitOnRequest);

    DBGPRINT("crashdd:\tPreparing I/O request...\n");

    //
    // Build an IRB for the request.
    // It is stored at a certain offset into the CRB.
    //
    status = CrashIdeBuildReadIrb(Extension, State, &irb, &crb);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to build request: %08x.\n");
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
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    normalPathDisabled = TRUE;

    DBGPRINT("crashdd:\tSending I/O request...\n");

    // There are two methods to complete the I/O, both experimental:
    //    1) call DispatchCrb() to send the IRB, then IdeDumpWaitOnRequest() to poll
    //    2) call miniport HwStartIo directly then poll manually by calling miniport's HwInterrupt()
    //
    if (IDE_METHOD == 1)
    {
        //
        // Prepare the IPI request
        //
        ipiRequest.Crb = (PVOID)crb;
        ipiRequest.DumpExtension = State->DumpPortDriver.Extension;
        ipiRequest.DumpWaitOnRequest = (PVOID)dumpIdeWaitOnRequest;
        ipiRequest.OperatingSystem = Extension->OperatingSystem;
        ipiRequest.IoFunctionPointer = (PVOID)State->DumpPortDriver.IoFunctionPointer;

        ipiArgument.Barrier = 1;
        ipiArgument.Context = &ipiRequest;
        ipiArgument.Callback = CrashIdeIpiSendRequestToPortDriver;

        status = (NTSTATUS)KeIpiGenericCall(CallIpiBroadcastFunction, 
                                            (ULONG_PTR)&ipiArgument);
    }
    else
    {
        //
        // Prepare the IPI request
        //
        ipiRequest.Irb = &irb;
        ipiRequest.DumpExtension = State->DumpPortDriver.Extension;

        ipiArgument.Barrier = 1;
        ipiArgument.Context = &ipiRequest;
        ipiArgument.Callback = CrashIdeIpiSendRequestToMiniportDriver;

        status = (NTSTATUS)KeIpiGenericCall(CallIpiBroadcastFunction, 
                                            (ULONG_PTR)&ipiArgument);
    }

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tRequest failed with status %08x\n", status);
        goto Exit;
    }

    //
    // BUG:  Check that BytesRead equals requested size
    //

    NT_ASSERT(irb.DataBuffer != NULL);

    //
    // Propagate to caller
    //
    RtlCopyMemory(Extension->UserRequest->OutputBuffer,
                  irb.DataBuffer,
                  Extension->UserRequest->Size);

Exit:

    DBGPRINT("crashdd:\tEnabling the normal I/O path...\n");

    //
    // Re-enable the normal I/O path by unlocking the scsiport queue
    //
    if (normalPathDisabled != FALSE)
    {
        status = ToggleNormalIoPath(State->DiskDeviceInformation.DeviceObject, TRUE);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("\ncrashdd:  Could not re-enable normal I/O path:  %08x\n", status);
            status = STATUS_UNSUCCESSFUL;
        }
    }

    if (irb.DataBuffer != NULL)
    {
        ExFreePoolWithTag(irb.DataBuffer, CRASHDD_TAG);
    }

    return status;
}

///=========================================================================
/// CrashIdeBuildReadIrb()
///
/// <summary>
/// Sets up an IDE_REQUEST_BLOCK to read the MBR.  On return, the CRB inside
/// the device extension structure has been updated to point to an allocated
/// IRB (freed by caller).
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// Note this code is specific to 512-byte MBR
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
CrashIdeBuildReadIrb (
    __in PCRASHDD_EXTENSION Extension,
    __in PCRASH_DUMP_STATE State,
    __inout PIDE_REQUEST_BLOCK Irb,
    __out PULONG_PTR Crb
    )
{
    NTSTATUS status;
    ULONG_PTR extension;
    ULONG_PTR irbOffset;
    ULONG_PTR callback;

    NT_ASSERT(State != NULL);
    NT_ASSERT(Irb != NULL);
    NT_ASSERT(Crb != NULL);
    NT_ASSERT(Extension != NULL);
    NT_ASSERT(State->DumpPortDriver.Extension > 0);
   
    extension = State->DumpPortDriver.Extension;
    Irb->DataBuffer = NULL;

    //
    // Find the CRB, which has info we need about the channel to send an IRB.
    //
    #ifndef _AMD64_
    *Crb = extension + DUMPATA_DEVEXT_CRB_OFFSET_32;
    #else
    *Crb = extension + DUMPATA_DEVEXT_CRB_OFFSET_64;
    #endif

    DBGPRINT("crashdd:\tCRB at 0x%08x.\n", *Crb);

    //
    // NB:  Freed by caller (on success)
    //
    Irb->DataBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, 
                                                    sizeof(IDE_REQUEST_BLOCK), 
                                                    CRASHDD_TAG);

    if (Irb->DataBuffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Prepare IRB  
    //
    RtlZeroMemory(Irb,sizeof(IDE_REQUEST_BLOCK));

#ifndef _AMD64_
    Irb->Channel = *(PUCHAR)(*Crb + DUMPATA_DEVEXT_CHANNEL_OFFSET_32);
    Irb->TargetId = *(PUCHAR)(*Crb + DUMPATA_DEVEXT_TARGETID_OFFSET_32);
    Irb->Lun = *(PUCHAR)(*Crb + DUMPATA_DEVEXT_LUN_OFFSET_32);
#else
    Irb->Channel = *(PUCHAR)(Crb + DUMPATA_DEVEXT_CHANNEL_OFFSET_64);
    Irb->TargetId = *(PUCHAR)(Crb + DUMPATA_DEVEXT_TARGETID_OFFSET_64);
    Irb->Lun = *(PUCHAR)(Crb + DUMPATA_DEVEXT_LUN_OFFSET_64);
#endif

    Irb->Function = IRB_FUNCTION_ATA_READ;//IRB_FUNCTION_ATAPI_COMMAND;
    //Notes on flags:
    //     -"data in" means SYSTEM <-- DEVICE (we are copying data FROM disk to buffer in memory)
    //     - all these flags are used in crash dump write CDB (replace SRB_FLAGS_DATA_IN with _OUT)
    Irb->IrbFlags = IRB_FLAGS_DATA_IN | IRB_FLAGS_MAP_BUFFERS ;//| IRB_FLAGS_DRDY_REQUIRED;//| IRB_FLAGS_USE_DMA;
    
    //outIrb->SenseInfoBufferLength = 0;
    Irb->DataTransferLength = Extension->UserRequest->Size;
    //outIrb->DataBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, 512, CRASHDD_TAG);
    //if (!outIrb->DataBuffer)
    //    return FALSE;
    //RtlZeroMemory(outIrb->DataBuffer,512);
    //outIrb->SenseInfoBuffer = NULL;
    Irb->TimeOutValue = 10;
    //research into the dump miniport atapi!AtapiHandleAtaCommand shows that this field
    //is actually required, unlike in an SRB.  It holds a pointer to its own function..
    //outIrb->IrbExtension = (PVOID)ExAllocatePoolWithTag(NonPagedPool, sizeof(DWORD_PTR), CRASHDD_TAG);
    //if (!outIrb->IrbExtension)
    //    return FALSE;

    //
    // BUGBUG:  Must set sector count/number to the requested one
    // from UserRequest field
    //
    Irb->IdeTaskFile.Current.bCommandReg = IDE_COMMAND_READ;
    Irb->IdeTaskFile.Current.bSectorCountReg = 1;
    Irb->IdeTaskFile.Current.bSectorNumberReg = 1;    
    Irb->IdeTaskFile.Current.bDriveHeadReg = 0xa0;  //formula from reversing dumpata:  ((!driverNumber-1)&0xF0)-0x50 = A0, assuming driveNumber is 1

    //
    // Store IRB at correct offset in device extension.
    //
#ifndef _AMD64_
    irbOffset = *Crb + DUMPATA_DEVEXT_IRB_OFFSET_32;
#else
    irbOffset = *Crb + DUMPATA_DEVEXT_IRB_OFFSET_64;
#endif

    RtlCopyMemory((PVOID)irbOffset, Irb, sizeof(IDE_REQUEST_BLOCK));

    DBGPRINT("crashdd:\tIRB stored in Device Extension at %08x...\n", irbOffset);

    //
    // Store a completion callback pointer
    //
    callback = extension + DUMPATA_DEVEXT_COMPLETION_CALLBACK_OFFSET;
    *(ULONG_PTR*)callback = (ULONG_PTR)CrashIdeCrbCompletionCallback;

    status = STATUS_SUCCESS;

Exit:

    if (!NT_SUCCESS(status))
    {
        if (Irb->DataBuffer != NULL)
        {
            ExFreePoolWithTag(Irb->DataBuffer, CRASHDD_TAG);
            Irb->DataBuffer = NULL;
        }
    }

    return status;
}

///=========================================================================
/// CrashIdeGetIoFunction()
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
CrashIdeGetIoFunction (
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
    // For all versions of Windows prior to Windows 8, we find DispatchCrb.
    //
    if (Extension->OperatingSystem != Win8)
    {
        #ifndef _AMD64_
        status = ScanDriverSection(".text",
                                   5,
                                   State->DumpPortDriver.BaseAddress,
                                   DUMPATA_DISPATCHCRB_MAGIC_32,
                                   DUMPATA_DISPATCHCRB_DISTANCE_UP_32,
                                   &State->DumpPortDriver.IoFunctionPointer);
        #else
        status = ScanDriverSection(".text",
                                   5,
                                   State->DumpPortDriver.BaseAddress,
                                   DUMPATA_DISPATCHCRB_MAGIC_64,
                                   DUMPATA_DISPATCHCRB_DISTANCE_UP_64,
                                   &State->DumpPortDriver.IoFunctionPointer);
        #endif

        RtlInitUnicodeString(&name, L"DispatchCrb");
    }
    else
    {
        //
        // TODO:  Add Win8 x64 support
        // Note: should not get to this assert since this OS incompatibility
        // is checked in our DriverEntry.
        //
        NT_VERIFY(Extension->Is64bit == FALSE);

        RtlInitUnicodeString(&name, L"Unknown");
        
        status = STATUS_NOT_SUPPORTED;

        NT_ASSERT(FALSE);
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
    DBGPRINT("crashdd:\tIDE I/O function %ws found at address %08x.\n", 
            State->DumpPortDriver.IoFunctionPointer);

Exit:

    return status;
}

///=========================================================================
/// CrashIdeCrbCompletionCallback()
///
/// <summary>
/// Completion routine called by IDE miniport when IRB is completed.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// This callback is experimental.
/// </remarks>
///========================================================================= 
PVOID
CrashIdeCrbCompletionCallback (
    __in PVOID Crb
    )
{
    IDE_REQUEST_BLOCK* irb;

    NT_ASSERT(FALSE);

#ifndef _AMD64_
    irb = (IDE_REQUEST_BLOCK*)((ULONG_PTR)Crb + DUMPATA_DEVEXT_IRB_OFFSET_32);
#else
    irb = (IDE_REQUEST_BLOCK*)((ULONG_PTR)Crb + DUMPATA_DEVEXT_IRB_OFFSET_64);
#endif

    DBGPRINT("crashdd:\tCrbCompletionCallback():\n");
    DBGPRINT("crashdd:\tstatus:\n");
    DBGPRINT("     Irb.IrbStatus = %08x\n",irb->IrbStatus);
    DBGPRINT("     Irb.AtaStatus = %08x\n",irb->AtaStatus);
    DBGPRINT("     Irb.AtaError = %08x\n",irb->AtaError);

    return Crb;
}

///=========================================================================
/// CrashIdeIpiSendRequestToPortDriver()
///
/// <summary>
/// Transmits the CRB/IRB request to the dump port driver and uses the port
/// driver to poll.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// This function must be called from the IPI broadcast routine, which 
/// insures that it runs only on a single processor.  Other crash dump
/// environment restrictions must be in effect before calling this function.
///
/// This callback is experimental.
/// Status as of 3/13/2012 - this "works" but garbage is returned for the mbr.
///
/// </remarks>
///========================================================================= 
ULONG_PTR
CrashIdeIpiSendRequestToPortDriver (
    __in ULONG_PTR Argument
    )
{
    NTSTATUS status;
    PIDE_IPI_REQUEST ipiRequest;
    ULONG_PTR extension;
    PIDE_REQUEST_BLOCK irb;
    PIDEDUMPWAITONREQUEST waitRoutine;
    ULONG_PTR irbOffset;
    PDISPATCH_CRB ioRoutine;
    PVOID crb;

    NT_ASSERT(Argument != 0);

    ipiRequest = (PIDE_IPI_REQUEST)Argument;
    extension = ipiRequest->DumpExtension;
    irb = ipiRequest->Irb;
    ioRoutine = (PDISPATCH_CRB)ipiRequest->IoFunctionPointer;
    crb = ipiRequest->Crb;
    waitRoutine = (PIDEDUMPWAITONREQUEST)ipiRequest->DumpWaitOnRequest;

    NT_ASSERT(extension != 0);
    NT_ASSERT(irb != NULL);
    NT_ASSERT(ioRoutine != NULL);
    NT_ASSERT(crb != NULL);
    NT_ASSERT(waitRoutine != NULL);

    //
    // Call DispatchCrb.
    //
    status = ioRoutine(crb);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // Use dump port driver's polling.
    //
    status = waitRoutine(crb, 0);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // Copy the resulting IRB in the CRB into our IRB
    //
    #ifndef _AMD64_
    irbOffset = (ULONG_PTR)crb + DUMPATA_DEVEXT_IRB_OFFSET_32;
    #else
    irbOffset = (ULONG_PTR)crb + DUMPATA_DEVEXT_IRB_OFFSET_64;
    #endif

    NT_ASSERT(irb->DataBuffer != NULL);

    RtlCopyMemory(irb->DataBuffer, (PVOID)irbOffset, sizeof(IDE_REQUEST_BLOCK));

Exit:

    return (ULONG_PTR)status;
}

///=========================================================================
/// CrashIdeIpiSendRequestToMiniportDriver()
///
/// <summary>
/// Transmits the CRB/IRB request directly to the dump miniport driver, 
/// completely bypassing the dump port driver.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// This function must be called from the IPI broadcast routine, which 
/// insures that it runs only on a single processor.  Other crash dump
/// environment restrictions must be in effect before calling this function.
///
/// This callback is experimental.
/// status as of 3/13/2012 - this "works" but Irb.IrbStatus is 2 
/// (data length mismatch) and Irb.AtaStatus is 0x20.  No idea..
///
/// Note: offsets used in calls to miniport are specific to WinXP.
///
/// </remarks>
///========================================================================= 
ULONG_PTR
CrashIdeIpiSendRequestToMiniportDriver (
    __in ULONG_PTR Argument
    )
{
    NTSTATUS status;
    BOOLEAN success;
    ULONG count;
    PIDE_IPI_REQUEST ipiRequest;
    ULONG_PTR extension;
    PIDE_REQUEST_BLOCK irb;
    ULONG i;

    NT_ASSERT(Argument != 0);

    ipiRequest = (PIDE_IPI_REQUEST)Argument;
    extension = ipiRequest->DumpExtension;
    irb = ipiRequest->Irb;

    NT_ASSERT(extension != 0);
    NT_ASSERT(irb != NULL);

    //
    // Call miniport HwStartIo routine directly
    // Example:  atapi!atapiHwStartIo
    //
    success = (*((BOOLEAN (__stdcall **)(ULONG_PTR, ULONG_PTR))extension + 46))
                                        (extension, (ULONG_PTR)irb); 

    //
    // The request was not issued successfully.
    //
    if (success == FALSE)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // The request was issued, now poll.
    //
    for(i = 0 ; i < 5 ; i++)
    {
        count = 1000;

        //
        // Call miniport's HwInterrupt routine directly
        // Example:  atapi!atapiHwInterrupt()
        // This interrupts the device to process our request.
        //
        while (count)
        {
            KeStallExecutionProcessor(10);

            if ((UCHAR)(*((int (__stdcall**)(ULONG_PTR))extension + 47))(extension))
            {
                break;
            }

            count-=10;
        }

        //
        // check status codes for success.
        //
        if (irb->IrbStatus == 1 || irb->IrbStatus == 0x44 || irb->IrbStatus == 2)
        {
            status = STATUS_SUCCESS;
            break;
        }

        //
        // Keep resending.
        //
        success = (*((BOOLEAN (__stdcall **)(ULONG_PTR, ULONG_PTR))extension + 46))
                                        (extension, (ULONG_PTR)irb);

        //
        // The request was not issued successfully.
        //
        if (success == FALSE)
        {
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }
    }

    status = STATUS_UNSUCCESSFUL;

Exit:

    return (ULONG_PTR)status;
}
