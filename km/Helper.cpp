
#include "Helper.hpp"

// 
// Used for IPI call barrier
//
static volatile LONG g_CpuNumber = 1;

///=========================================================================
/// ScanDriverTextSection()
///
/// <summary>
/// Attempts to locate the address of the supplied 'magic' bytes within the 
/// given section by name.  The distance value is added to the discovered
/// location, which should return the address of the function.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
ScanDriverSection (
    __in PCHAR SectionName,
    __in USHORT SectionNameLength,
    __in DWORD_PTR DriverBase, 
    __in ULONG Magic,
    __in ULONG Distance,
    __out PULONG_PTR Address
    )
{
    DWORD_PTR sectionAddress;
    ULONG sectionSize;
    ULONG offset; 
    NTSTATUS status;

    NT_ASSERT(DriverBase != 0);
    NT_ASSERT(Address != NULL);

    *Address = 0;
    offset = 0;

    status = GetSectionAddress(DriverBase,
                               SectionName,
                               SectionNameLength,
                               &sectionSize,
                               &sectionAddress);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tCould not locate a section named %s: %08x\n", 
                 SectionName,
                 status);
        goto Exit;
    }

    //
    // Scan section for magic bytes.
    //
    while ((offset + 4) < sectionSize)
    {
        if ( (*((PULONG)(sectionAddress + offset))) == Magic)
        {
            *Address = (DWORD_PTR)(sectionAddress + offset - Distance);
            status = STATUS_SUCCESS;
            goto Exit;
        }

        offset++;
    }

    status = STATUS_NOT_FOUND;

Exit:

    return status;
}

///=========================================================================
/// GetSectionAddress()
///
/// <summary>
/// Locates the address of the named section in the supplied image.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetSectionAddress (
    __in DWORD_PTR BaseAddress,
    __in PCHAR Text,
    __in USHORT TextLength,
    __inout PULONG SectionSize,
    __inout PULONG_PTR Address
    )
{
    ULONG tableSize;
    ULONG firstSection;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    DWORD_PTR start,curr,sectionCount;
    SIZE_T compare = 0;
    NTSTATUS status;

    NT_ASSERT(BaseAddress != NULL);
    NT_ASSERT(SectionSize != NULL);
    NT_ASSERT(Address != NULL);

    *Address = 0;
    *SectionSize = 0;

    ntHeader = RtlImageNtHeader((PVOID)BaseAddress);

    if (ntHeader == NULL)
    {
        DBGPRINT("crashdd:\tFailed to get nt header for image at %p.\n", BaseAddress);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    if (ntHeader->FileHeader.NumberOfSections == 0)
    {
        DBGPRINT("crashdd:\tImage at %p has no sections!\n", BaseAddress);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    dosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
    tableSize = sizeof(IMAGE_SECTION_HEADER) * ntHeader->FileHeader.NumberOfSections;
    firstSection = dosHeader->e_lfanew + sizeof(ULONG) + 
                   sizeof(IMAGE_FILE_HEADER) + ntHeader->FileHeader.SizeOfOptionalHeader;
    start = BaseAddress + firstSection;
    curr = start;
    sectionCount=0;

    while (sectionCount < ntHeader->FileHeader.NumberOfSections)
    {
        compare = RtlCompareMemory(((PIMAGE_SECTION_HEADER)curr)->Name, Text, TextLength);

        if (compare == 5)
        {
            *SectionSize = ((PIMAGE_SECTION_HEADER)curr)->Misc.VirtualSize;
            *Address = BaseAddress + ((PIMAGE_SECTION_HEADER)curr)->VirtualAddress;
            status = STATUS_SUCCESS;
            goto Exit;
        }

        curr += sizeof(IMAGE_SECTION_HEADER);
        sectionCount++; 
    }

    DBGPRINT("crashdd:\tUnable to find a section named '%s'.\n", Text);
    status = STATUS_NOT_FOUND;

Exit:

    return status;
}


///=========================================================================
/// GetImportAddressEntry64()
///
/// <summary>
/// Locates the address of the IAT function pointer in memory stored in 
/// the image thunk for the function name/module.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetImportAddressEntry64 (
    __in DWORD_PTR BaseAddress,
    __in PCHAR ModuleName,
    __in PCHAR FunctionName,
    __out PVOID* Address
    )
{
    PIMAGE_NT_HEADERS ntHeader;
    NTSTATUS status;
    PIMAGE_IMPORT_DESCRIPTOR iatRva;
    ULONG i;
    PSTR importName;
    PIMAGE_THUNK_DATA64 firstThunk;
    PIMAGE_THUNK_DATA64 originalThunk;
    PIMAGE_IMPORT_BY_NAME name;
    STRING moduleName;
    STRING functionName;
    STRING compare;

    NT_ASSERT(BaseAddress != NULL);
    NT_ASSERT(ModuleName != NULL);
    NT_ASSERT(FunctionName != NULL);
    NT_ASSERT(Address != NULL);

    *Address = NULL;
    RtlInitAnsiString(&moduleName, ModuleName);
    RtlInitAnsiString(&functionName, FunctionName);

    ntHeader = RtlImageNtHeader((PVOID)BaseAddress);

    if (ntHeader == NULL)
    {
        DBGPRINT("crashdd:\tFailed to get nt header for image at %p.\n", BaseAddress);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
    {
        DBGPRINT("crashdd:\tImage at %p has no IAT!\n", BaseAddress);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    iatRva = (PIMAGE_IMPORT_DESCRIPTOR)(BaseAddress + 
        ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    //
    // Loop over all modules in import table
    //
    for (i = 0; i < iatRva->Characteristics != 0; i++)
    {
        importName = (PSTR)(BaseAddress + iatRva[i].Name);

        if (importName == NULL)
        {
            continue;
        }

        RtlInitAnsiString(&compare, importName);

        if (RtlCompareString(&compare, &moduleName, TRUE) == 0)
        {
            if (iatRva[i].FirstThunk == NULL || iatRva[i].OriginalFirstThunk == NULL)
            {
                continue;
            }
         
            firstThunk = (PIMAGE_THUNK_DATA64)(BaseAddress + iatRva[i].FirstThunk);
            originalThunk = (PIMAGE_THUNK_DATA64)(BaseAddress + iatRva[i].OriginalFirstThunk);

            //
            // Loop over all imported functions
            //
            for (; originalThunk->u1.Function != NULL; firstThunk++, originalThunk++)
            {
                //
                // Skip ordinal-named entries
                //
                if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    continue;
                }

                name = (PIMAGE_IMPORT_BY_NAME)(BaseAddress + originalThunk->u1.AddressOfData);

                if (name == NULL)
                {
                    continue;
                }
    
                RtlInitAnsiString(&compare, name->Name);

                if (RtlCompareString(&compare, &functionName, TRUE) == 0)
                {
                    *Address = &firstThunk->u1.Function;
                    status = STATUS_SUCCESS;
                    goto Exit;
                }

            } // end loop over functions

        } // end module name match
                    
    } // end loop over modules

    DBGPRINT("crashdd:\tUnable to find a import named '%s' in module '%s'.\n",
             FunctionName,
             ModuleName);
    status = STATUS_NOT_FOUND;

Exit:

    return status;
}

///=========================================================================
/// PrepareForPatch()
///
/// <summary>
/// Maps read-only memory into an MDL that can be RWX, in preparation for
/// patching.  Caller must free MDL.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
PrepareForPatch (
    __in PVOID VirtualAddress,
    __in ULONG Size,
    __out PMDL* Mdl,
    __out PVOID* SystemAddress
    )
{
    NTSTATUS status;

    NT_ASSERT(Mdl != NULL);
    NT_ASSERT(*Mdl == NULL);

    //
    // Allocate an MDL to describe the pages to modify
    //
    *Mdl = IoAllocateMdl(VirtualAddress,
                         Size,
                         FALSE,
                         FALSE,
                         NULL);

    if (*Mdl == NULL)
    {
        DBGPRINT("crashdd:\tCould not allocate an MDL to patch\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Lock into memory
    //
    __try
    {
        MmProbeAndLockPages(*Mdl, 
                            KernelMode,
                            IoWriteAccess);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DBGPRINT("crashdd:\tAn exception occured attempting to lock the virtual buffer at %p\n", 
                 VirtualAddress);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Map them.
    //
    MmMapLockedPages(*Mdl, KernelMode);

    //
    // Change page permissions on the physical pages described in the MDL.
    //
    status = MmProtectMdlSystemAddress(*Mdl, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tCould not change page permissions on address %p: %08x\n", 
                 VirtualAddress,
                 status);
        goto Exit;
    }

    //
    // Get system address to modify the mapped memory
    //
    *SystemAddress = MmGetSystemAddressForMdlSafe(*Mdl, HighPagePriority);

    if (*SystemAddress == NULL)
    {
        DBGPRINT("crashdd:\tCould not get a system address for mapped address\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:

    return status;

}

///=========================================================================
/// Is64bitProcess()
///
/// <summary>
/// This function determines if the platform is 64-bit or not and optionally
/// whether the given process is 32-bit (wow'd) or not.
/// </summary>
/// <param name="eproc">pointer to an EPROCESS to attach to (optional)</param>
/// <returns>
/// If no eprocess is passed in, the function returns TRUE if the architecture
/// is 64-bit and FALSE if the architecture is 32-bit.
/// If an eprocess is passed in, the function returns TRUE only if both the
/// architecture AND the given process is 64-bit.  Otherwise, returns FALSE.
///</returns>
/// <remarks>
/// This function uses the presence or absence of the IoIs32bitProcess to
/// determine if the architecture supports 64-bit.
/// </remarks>
///=========================================================================
__checkReturn
NTSTATUS
Is64bitProcess (
    __in PEPROCESS Process,
    __out PBOOLEAN Is64Bit
    )
{
    UNICODE_STRING function;
    lpfnIoIs32bitProcess functionPointer;
    KAPC_STATE apc;
    NTSTATUS status;

    RtlInitUnicodeString(&function,L"IoIs32bitProcess");

    //
    // If the routine IoIs32bitProcess doesn't exist, 
    // we are gauranteed to be on a 32-bit platform.
    //
#pragma warning(disable:4055)
    functionPointer = (lpfnIoIs32bitProcess)MmGetSystemRoutineAddress(&function);

    if (functionPointer == NULL)
    {
        *Is64Bit = FALSE;
        status = STATUS_SUCCESS;
        goto Exit;
    }

    //
    // if no eprocess was passed in, we just want to know 
    // if we are 64-bit ARCHITECTURE.
    //
    if (Process == NULL)
    {
        *Is64Bit = TRUE;
        status = STATUS_SUCCESS;
        goto Exit;
    }

    status = STATUS_SUCCESS;
    *Is64Bit = TRUE;

    //
    // Attach to target process context to determine if it is truly 64-bit
    // or just wow64.
    //
    KeStackAttachProcess(Process, &apc);

    if (functionPointer(NULL))
    {
        *Is64Bit = FALSE;
    }

    KeUnstackDetachProcess(&apc);

Exit:

    return status;
}

///=========================================================================
/// <summary>
/// This routine "disables" or "enables" the normal I/O path by flushing and
/// locking the port driver's queue by sending special SRB's.
/// </summary>
/// <parameter> Enable[in] - enable or disable</parameter>
/// <returns>TRUE if successful, false if not.</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
NTSTATUS
ToggleNormalIoPath (
    __in PDEVICE_OBJECT DeviceObject,
    __in BOOLEAN Enable
    )
{
    NTSTATUS status;
    UCHAR function;
    ULONG flags;
    
    NT_ASSERT(DeviceObject != NULL);

    //
    // Send the lock/unlock request IRP
    //
    function = Enable ? SRB_FUNCTION_UNLOCK_QUEUE : SRB_FUNCTION_LOCK_QUEUE;
    flags = SRB_FLAGS_BYPASS_LOCKED_QUEUE | SRB_FLAGS_NO_QUEUE_FREEZE;

    status = SendSrbIrp(DeviceObject,
                        function,
                        flags);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tFailed to %s the port driver queue: %08x\n",
                 Enable ? "unlock" : "lock",
                 status);
        goto Exit;
    }

    //
    // If we are locking, additionally flush the queue.
    //
    if (Enable == FALSE)
    {
        function = SRB_FUNCTION_FLUSH_QUEUE;
        flags = SRB_FLAGS_BYPASS_LOCKED_QUEUE;

        status = SendSrbIrp(DeviceObject,
                            function,
                            flags);

        if (!NT_SUCCESS(status))
        {
            DBGPRINT("crashdd:\tFailed to flush the port driver queue: %08x\n",
                     status);
            goto Exit;
        }
    }

Exit:

    return status;
}

///=========================================================================
/// <summary>
/// This routine sends an IRP with an SRB.
/// </summary>
/// <returns>NTSTATUS</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
SendSrbIrp (
    __in PDEVICE_OBJECT DiskDeviceObject,
    __in UCHAR SrbFunction,
    __in ULONG SrbFlags
    )
{
    NTSTATUS status;
    PSCSI_REQUEST_BLOCK srb;
    PIRP irp;
    PKEVENT event;
    PIO_STACK_LOCATION ioStackLocation;

    NT_ASSERT(DiskDeviceObject != NULL);

    irp = NULL;
    srb = NULL;
    event = NULL;

    //
    // Build queue lock/unlock SRB
    //
    srb = (PSCSI_REQUEST_BLOCK)ExAllocatePoolWithTag(NonPagedPool, 
                                                     sizeof(SCSI_REQUEST_BLOCK), 
                                                     CRASHDD_TAG);

    if (srb == NULL)
    {
        DBGPRINT("crashdd:\tFailed to allocate an SRB.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
        
    RtlZeroMemory(srb,sizeof(SCSI_REQUEST_BLOCK));
    
    //
    // Prepare an IRP
    //
    irp = IoAllocateIrp(DiskDeviceObject->StackSize + 1, FALSE);

    if (irp == NULL)
    {
        DBGPRINT("crashdd:\tFailed to allocate an IRP.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Setup an event
    //
    event = (PKEVENT)ExAllocatePoolWithTag(NonPagedPool, 
                                           sizeof(KEVENT), 
                                           CRASHDD_TAG);

    if (event == NULL)
    {
        DBGPRINT("crashdd:\tFailed to allocate an event.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    KeInitializeEvent(event, NotificationEvent, FALSE);
    srb->Length = sizeof(SCSI_REQUEST_BLOCK);
    srb->Function = SrbFunction;
    srb->SrbFlags = SrbFlags;
    srb->OriginalRequest = irp;
    srb->QueueTag = 0xff;

    ioStackLocation = IoGetNextIrpStackLocation(irp);

    //
    // undocumented settings to force queue lock/unlock.
    // reversed from scsiport.sys!SpLockUnlockQueue.
    // doing it the way MSDN documents it always fails with INVALID_REQUEST.
    //
    ioStackLocation->Parameters.Scsi.Srb = srb;
    ioStackLocation->MajorFunction = IRP_MJ_SCSI;
    ioStackLocation->Control = 0xe0;
    IoSetCompletionRoutine(irp, IrpCompletionRoutine, event, TRUE, TRUE, TRUE);

    //
    // Send IRP to port driver
    //
    status = IoCallDriver(DiskDeviceObject, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:\tCould not send IRP to port driver:  %08x\n", status);
        goto Exit;
    }
    
Exit:

    if (irp != NULL)
    {
        IoFreeIrp(irp);
    }

    if (srb != NULL)
    {
        ExFreePoolWithTag(srb, CRASHDD_TAG);
    }

    if (event != NULL)
    {
        ExFreePoolWithTag(event, CRASHDD_TAG);
    }

    return status;
}

///=========================================================================
/// <summary>
/// This is the SRB IRP completion routine.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
NTSTATUS
IrpCompletionRoutine (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp,
    __in PVOID Context
    )
{
    DBG_UNREFERENCED_PARAMETER(DeviceObject);
    DBG_UNREFERENCED_PARAMETER(Irp);

    NT_ASSERT(Context != NULL);

    KeSetEvent((PKEVENT)Context, 0, FALSE);

    //
    // We signal to the I/O mgr that more processing is required,
    // because the dispatch function is waiting on the event.
    // Also, because we allocated the IRP and will immediately free
    // it on completion, so I/O mgr should not continue processing it.
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

///=========================================================================
/// <summary>
/// This is an IPI broadcast worker function which insures that the specified
/// target callback function executes on a single processor.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
ULONG_PTR
CallIpiBroadcastFunction ( 
    __in ULONG_PTR Argument
    )
{
    NTSTATUS status;
    PIPI_CALL_ARGUMENT ipiArgument;

    ipiArgument = (PIPI_CALL_ARGUMENT)Argument;

    NT_ASSERT(ipiArgument != NULL);
    NT_ASSERT(ipiArgument->Callback != NULL);
    NT_ASSERT(ipiArgument->Context != NULL);

    //
    // If we are not running on CPU 0, spin until CPU 0 releases us.
    //
    if (InterlockedDecrement(&g_CpuNumber) != 0)
    {
        while (ipiArgument->Barrier == 1)
        {
            YieldProcessor();
        }
        
        //
        // KeIpiGenericCall only returns the value returned
        // from the instance on CPU 0, so this is irrelevant..
        //
        status = STATUS_SUCCESS;
    }
    //
    // We are on CPU 0, do the work.
    //
    else
    {
        status = (NTSTATUS)ipiArgument->Callback((ULONG_PTR)ipiArgument->Context);

        //
        // Release other CPUs
        //
        ipiArgument->Barrier = 0;

        //
        // Reset global var for next broadcast call
        //
        g_CpuNumber = 1;
    }

    return (ULONG_PTR)status;
}


///=========================================================================
/// <summary>
/// Probes and locks the user buffer and returns a system address.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
__checkReturn
NTSTATUS
GetUserBuffer (
    __in PVOID UserBuffer,
    __in ULONG UserBufferLength,
    __out PMDL* Mdl,
    __out PVOID* SystemAddress,
    __in BOOLEAN Write
    )
{
    NTSTATUS status;
    LOCK_OPERATION lockOperation;

    NT_ASSERT(UserBuffer != NULL);
    NT_ASSERT(UserBufferLength > 0);
    NT_ASSERT(Mdl != NULL);
    NT_ASSERT(*Mdl == NULL);
    NT_ASSERT(SystemAddress != NULL);
    NT_ASSERT(*SystemAddress == NULL);

    *Mdl = NULL;
    *SystemAddress = NULL;

    //
    // Make sure valid address
    //
    __try
    {
        if (Write != FALSE)
        {
            ProbeForWrite(UserBuffer, UserBufferLength, 1);
            lockOperation = IoWriteAccess;
        }
        else
        {
            ProbeForRead(UserBuffer, UserBufferLength, 1);
            lockOperation = IoReadAccess;
        }
    }
    __except(EXCEPTION_CONTINUE_EXECUTION)
    {
        DBGPRINT("crashdd:\tException trying to probe user buffer at %p\n",
                 UserBuffer);
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    //
    // Lock in buffer using MDL
    //
    *Mdl = IoAllocateMdl(UserBuffer, 
                         UserBufferLength, 
                         FALSE, 
                         FALSE, 
                         NULL);

    if (*Mdl == NULL)
    {
        DBGPRINT("crashdd:\tFailed to allocate an MDL\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    __try
    {
        MmProbeAndLockPages(*Mdl, KernelMode, lockOperation);
    }
    __except(EXCEPTION_CONTINUE_EXECUTION)
    {
        DBGPRINT("crashdd:\tException trying to lock pages at user address %p\n", 
                 UserBuffer);
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    *SystemAddress = MmGetSystemAddressForMdlSafe(*Mdl, NormalPagePriority);

    if (*SystemAddress == NULL)
    {
        DBGPRINT("crashdd:\tFailed to get system address for user buffer at %p\n",
                 UserBuffer);
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:

    if (!NT_SUCCESS(status))
    {
        if (*Mdl != NULL)
        {
            __try
            {
                MmUnlockPages(*Mdl);
            }
            __except(EXCEPTION_CONTINUE_EXECUTION)
            {

            }
            IoFreeMdl(*Mdl);
        }   
    }

    return status;
}