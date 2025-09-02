
#include "DriverMain.hpp"

//
// Global static pointer to our device extension, provided by the
// I/O manager when we create our device object.
// This holds all of our program state.
//
static PCRASHDD_EXTENSION g_DeviceExtension;

extern "C"
{
///=========================================================================
/// DriverEntry()
///
/// <summary>
/// Driver entry point.
/// </summary>
/// <param name="theDriverObject">driver object passed by kernel</param>
/// <param name="theRegistryPath">pointer to our reg config block</param>
/// <returns>NTSTATUS</returns>
/// <remarks>
/// 
/// </remarks>
///=========================================================================   
NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;    
    ULONG i;
    PDEVICE_OBJECT deviceObject;
    UNICODE_STRING device;
    UNICODE_STRING deviceLink;

    DBG_UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Setup dispatch table
    //
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) 
    {
        DriverObject->MajorFunction[i] = DispatchControl;
    }

    DriverObject->DriverUnload = Unload;

    //
    // Create device object and link
    //
    RtlInitUnicodeString(&device, crashddDeviceName);
    RtlInitUnicodeString(&deviceLink, crashddDeviceNameLink);

    status = IoCreateDevice(DriverObject,
                            sizeof(CRASHDD_EXTESION),
                            &device,
                            FILE_DEVICE_CRASHDD,
                            0,
                            FALSE,
                            &deviceObject);

    if(!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:  Failed to create device:  %08x\n", status);
        goto Exit;
    }
    
    NT_ASSERT(deviceObject != NULL);

    status = IoCreateSymbolicLink(&deviceLink, &device);

    if(!NT_SUCCESS(status)) 
    {
        DBGPRINT("crashdd:  Failed to create link to device:  %08x\n", status);
        IoDeleteDevice(deviceObject);
        goto Exit;
    }

    //
    // Initialize our device extension
    //
    g_DeviceExtension = (PCRASHDD_EXTENSION)deviceObject->DeviceExtension;
    g_DeviceExtension->DriverObject = DriverObject;

    status = InitializeDeviceExtension(g_DeviceExtension);

    if (!NT_SUCCESS(status))
    {
        DBGPRINT("crashdd:  Failed to initialize device extension:  %08x\n", status);
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:

    return status;
}

///=========================================================================
/// Unload()
///
/// <summary>
/// Unloads our driver and cleans up device.
/// </summary>
/// <param name="driverobject">our drivers object</param>
/// <returns>n/a</returns>
/// <remarks>
///
/// </remarks>
///=========================================================================
VOID
Unload (
    __in PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING string;

    RtlInitUnicodeString(&string, crashddDeviceNameLink);
    IoDeleteSymbolicLink(&string);

    if(!DriverObject)
    {
        return;
    }

    if (DriverObject->DeviceObject)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    return;
}

///=========================================================================
/// DispatchControl()
///
/// <summary>
/// Dispatch routine.
/// </summary>
/// <param name="deviceObject">device object</param>
/// <param name="Irp">input irp to process</param>
/// <returns>NTSTATUS</returns>
/// <remarks>
///
/// </remarks>
///=========================================================================
NTSTATUS
DispatchControl (
    __in PDEVICE_OBJECT DeviceObject,
    __in PIRP Irp
    )
{
    PIO_STACK_LOCATION irpStack;
    PVOID outputBuffer;
    ULONG outputBufferLength;
    ULONG inputBufferLength;
    ULONG information;
    ULONG ioControlCode;
    NTSTATUS status;

    DBG_UNREFERENCED_PARAMETER(DeviceObject);
     
    information = 0;
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    switch (irpStack->MajorFunction) 
    {
        case IRP_MJ_DEVICE_CONTROL:
        {
            DBGPRINT("crashdd:  Received control code %08x\n",ioControlCode);

            switch (ioControlCode) 
            {
                //
                // Use crash dump stack to read disk.
                //
                case IOCTL_READ_DISK:
                {
                    //
                    // Both input and output buffers should point to the same argument.
                    //
                    if ((outputBuffer == NULL) || (outputBufferLength != sizeof(CRASHDD_REQUEST)) || 
                         (inputBufferLength != sizeof(CRASHDD_REQUEST)))
                    {
                        DBGPRINT("crashdd:  Invalid UserRequest structure at %p or bad length (%08x).\n", 
                                 outputBuffer,
                                 outputBufferLength);
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }

                    g_DeviceExtension->UserRequest = (PCRASHDD_REQUEST)outputBuffer;

                    //
                    // Basic argument validation - further checks done in CrashDumpStackRead
                    //
                    if (g_DeviceExtension->UserRequest->OutputBuffer == NULL)
                    {
                        DBGPRINT("crashdd:  UserRequest must contain a valid buffer.\n");
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }

                    if (g_DeviceExtension->UserRequest->Size <= 0 || 
                        g_DeviceExtension->UserRequest->Size > MAX_READ_SIZE)
                    {
                        DBGPRINT("crashdd:\tInvalid request size %lu\n",
                                 g_DeviceExtension->UserRequest->Size);
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }

                    DBGPRINT("crashdd:  User request parameters:\n");
                    DBGPRINT("crashdd:\tSize: %lu\n",
                             g_DeviceExtension->UserRequest->Size);
                    DBGPRINT("crashdd:\tOffset: %I64u\n",
                             g_DeviceExtension->UserRequest->Offset);

                    status = CrashDumpStackRead(g_DeviceExtension);

                    //
                    // A successful read always returns exactly the size of the
                    // input struct.  The actual bytes read from disk is stored
                    // in a field in this struct.
                    //
                    if (NT_SUCCESS(status))
                    {
                        information = sizeof(CRASHDD_REQUEST);
                    }

                    break;
                }
                default:
                {
                    status = STATUS_INVALID_DEVICE_REQUEST;
                    break;
                }
            }
            break;
        }    
        case IRP_MJ_CREATE:
        case IRP_MJ_SHUTDOWN:
        case IRP_MJ_CLOSE:
        case IRP_MJ_CLEANUP:
        {
            status = STATUS_SUCCESS;
            break;    
        }
        default:
        {
            DBGPRINT("crashdd:  Received invalid major function code: %08x\n",
                    irpStack->MajorFunction);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

///=========================================================================
/// InitializeDeviceExtension()
///
/// <summary>
/// Sets up our device extension structure.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// "Recognized" platforms are:
///     Windows 2000 SP4
///     Windows XP x86 SP2 and SP3
///     Windows XP x64
///     Windows Server 2003 x86/x64 SP2
///     Windows Vista x86/x64 SP2
///     Windows 7 x86/x64 SP1
///     Windows Server 2008 R2 SP1
///     Windows 8 Release Preview, x86/x64
/// </remarks>
///=========================================================================  
__checkReturn
NTSTATUS
InitializeDeviceExtension (
    __inout PCRASHDD_EXTENSION Extension
    )
{
    NTSTATUS status;
    RTL_OSVERSIONINFOEXW info;
    UNICODE_STRING name;

    RtlZeroMemory(&info, sizeof(info));
    RtlZeroMemory(&name, sizeof(name));

    NT_ASSERT(Extension != NULL);

    //
    // Get version info for OS
    //
    info.dwOSVersionInfoSize = sizeof(info);

    status = RtlGetVersion((PRTL_OSVERSIONINFOW)&info);

    if(!NT_SUCCESS(status)) 
    {
        DBGPRINT("crashdd:  Failed to get versionInfo struct:  %08x\n", status);
        goto Exit;
    }

    //
    // Check for 64-bit platform
    //
    status = Is64bitProcess(NULL, &Extension->Is64bit);

    if(!NT_SUCCESS(status)) 
    {
        DBGPRINT("crashdd:  Could not determine architecture bitness:  %08x\n", status);
        goto Exit;
    }

    //
    // Determine os build
    //
    switch (info.dwMajorVersion)
    {
        case 5:
        {
            switch (info.dwMinorVersion)
            {
                case 0:
                {
                    RtlInitUnicodeString(&name, L"Windows 2000");

                    if (info.wServicePackMajor != 4)
                    {
                        DBGPRINT("crashdd:  Unsupported service pack level %i!\n",
                                info.wServicePackMajor);
                        goto Unsupported;
                    }

                    Extension->OperatingSystem = Win2k;
                    goto Success;
                }
                case 1:
                {
                    RtlInitUnicodeString(&name, L"Windows XP");

                    NT_ASSERT(Extension->Is64bit == FALSE);

                    if ((info.wServicePackMajor != 2) &&
                        (info.wServicePackMajor != 3))
                    {
                        DBGPRINT("crashdd:  Unsupported service pack level %i!\n",
                            info.wServicePackMajor);
                        goto Unsupported;
                    }

                    Extension->OperatingSystem = WinXPSp23;
                    goto Success;
                }
                case 2:
                {
                    //
                    // SP2 is only supported for XP x64, Win2k3 x86 and x64
                    //
                    if (info.wServicePackMajor != 2)
                    {
                        RtlInitUnicodeString(&name, L"Windows XP or Windows 2003");
                        DBGPRINT("crashdd:  Unsupported service pack level %i!\n",
                            info.wServicePackMajor);
                        goto Unsupported;
                    }

                    Extension->OperatingSystem = Win2k3sp2;

                    if (Extension->Is64bit != FALSE)
                    {
                        RtlInitUnicodeString(&name, L"Windows XP or Windows 2003");
                        goto Success;
                    }

                    RtlInitUnicodeString(&name, L"Windows 2003");
                    goto Success;
                }
                default:
                {
                    NT_ASSERT(FALSE);
                    DBGPRINT("crashdd:  Unsupported major/minor version %lu.%lu\n",
                            info.dwMajorVersion,
                            info.dwMinorVersion);
                    goto Unsupported;
                }

            } // end minor version switch

            break;

        } // end major 5 case
        case 6:
        {
            switch (info.dwMinorVersion)
            {
                case 0:
                {
                    RtlInitUnicodeString(&name, L"Windows Vista or Server 2008");

                    if (info.wServicePackMajor != 2)
                    {
                        DBGPRINT("crashdd:  Unsupported service pack level %i!\n",
                                info.wServicePackMajor);
                        goto Unsupported;
                    }

                    Extension->OperatingSystem = WinVista_Sp2;
                    goto Success;
                }
                case 1:
                {
                    RtlInitUnicodeString(&name, L"Windows 7 or Server 2008 R2");

                    if (info.wServicePackMajor != 1)
                    {
                        DBGPRINT("crashdd:  Unsupported service pack level %i!\n",
                            info.wServicePackMajor);
                        goto Unsupported;
                    }

                    Extension->OperatingSystem = Win7_2008R2_sp1;
                    goto Success;
                }
                case 2:
                {
                    RtlInitUnicodeString(&name, L"Windows 8 RP");

                    Extension->OperatingSystem = Win8;
                    goto Success;
                }
                default:
                {
                    NT_ASSERT(FALSE);
                    DBGPRINT("crashdd:  Unsupported major/minor version %lu.%lu\n",
                            info.dwMajorVersion,
                            info.dwMinorVersion);
                    goto Unsupported;
                }

            } //end minor version switch

            break;
 
        } //end major 6 case
        default:
        {
            NT_ASSERT(FALSE);
            DBGPRINT("crashdd:  Unsupported major version %lu\n",
                    info.dwMajorVersion);
            goto Unsupported;
        } //end default case

    } //end switch over major version

Unsupported:
    status = STATUS_NOT_SUPPORTED;
    goto Exit;

Success:

    if (Extension->Is64bit != FALSE)
    {
        Extension->DriverObjectModuleListOffset = 0x14 * 2;
    }
    else
    {
        Extension->DriverObjectModuleListOffset = 0x14;
    }

    NT_ASSERT(name.Buffer != NULL);

    DBGPRINT("crashdd:  Detected %ws %ws SP%i\n",
            name.Buffer,
            (Extension->Is64bit != FALSE) ? L"64-bit" : L"32-bit",
            info.wServicePackMajor);

    status = STATUS_SUCCESS;    

Exit:

    return status;
}
} //end extern "C"