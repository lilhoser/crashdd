
#include "main.hpp"

using namespace std;

///=========================================================================
/// main()
///
/// <summary>
/// Main console program
/// </summary>
/// <returns>0 on success, 1 on failure</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
INT
wmain (
    __in INT Argc, 
    __in PWCHAR Argv[]
    )
{
    INT result;
    ULONGLONG offset;
    ULONG size;
    ULONG error;
    INT i;
    PWCHAR input;
    PWCHAR output;
    FILE* fp;
    CRASHDD_REQUEST request;
    errno_t error2;
    PWCHAR argument;
    PWCHAR value;
    PWCHAR key;

    //
    // Assume error
    //
    result = 1;
    input = NULL;
    output = NULL;
    memset(&request, 0, sizeof(request));

    if (Argc < 4)
    {
        Usage(TooFewArguments);
        goto Exit;
    }

    if (Argc > 5)
    {
        Usage(TooManyArguments);
        goto Exit;
    }

    //
    // Parse arguments
    //
    for (i = 1; i < Argc; i++)
    {
        argument = Argv[i];
        value = NULL;
        key = wcstok_s(argument, L"=", &value);

        if (key == NULL || value == NULL)
        {
            Usage(InvalidArgument);
            goto Exit;
        }

        if (wcslen(key) == 0 || wcslen(value) == 0)
        {
            Usage(InvalidArgument);
            goto Exit;
        }

        if (_wcsicmp(key, L"-if") == 0)
        {
            input = value;
        }
        else if (_wcsicmp(key, L"-of") == 0)
        {
            output = value;
        }
        else if (_wcsicmp(key, L"-offset") == 0)
        {
            offset = _wcstoui64(value, L'\0', 10);
        }
        else if (_wcsicmp(key, L"-size") == 0)
        {
            size = wcstoul(value, L'\0', 10);
        }
        else
        {
            Usage(InvalidArgument);
            goto Exit;
        }
    }

    if (output == NULL)
    {
        Usage(InvalidOutputFile);
        goto Exit;
    }

    if (offset > MAXULONGLONG)
    {
        Usage(InvalidReadOffset);
        goto Exit;
    }

    if (size > MAX_READ_SIZE || size <= 0)
    {
        Usage(InvalidReadSize);
        goto Exit;
    }

    //
    // Allocate output buffer
    //
    request.OutputBuffer = (PVOID)calloc((size_t)size, sizeof(UCHAR));

    if (request.OutputBuffer == NULL)
    {
        printf("Failed to allocate buffer of size %lu\n", size);
        goto Exit;
    }

    if (input != NULL)
    {
        request.DeviceName.Buffer = input;
        request.DeviceName.Length = wcslen(input) * sizeof(wchar_t);
        request.DeviceName.MaximumLength = request.DeviceName.Length;
    }

    request.Offset = offset;
    request.Size = size;

    printf("Sending request at %p:\n" \
           "\tdevice = %ws\n\toffset = %I64u\n\tsize = %lu\n\toutput buffer at %p...\n",
           &request,
           request.DeviceName.Buffer,
           offset,
           size,
           request.OutputBuffer);

    //
    // Issue request
    //
    error = CrashDumpRead(&request, &size);

    if (error > 0)
    {
        printf("Read attempt failed with error %08x\n", error);
        goto Exit;
    }

    //  
    // A successful read always returns the size of the input struct.
    //
    if (size != sizeof(request))
    {
        printf("Read attempt failed - returned size %lu should be %lu\n",
               size,
               sizeof(request));
        goto Exit;
    }

    //
    // The actual size of data read from the drive.
    //
    size = request.BytesRead;

    printf("Successfully read %lu bytes from offset %I64u!\n", size, offset);

    //
    // Write to output file
    //
    error2 = _wfopen_s(&fp, output, L"wb");

    if (error2 != 0)
    {
        printf("Failed to open output file %ws for writing: %i\n", output, error2);
        goto Exit;
    }

    fwrite(request.OutputBuffer, size, sizeof(UCHAR), fp);
    fclose(fp);

    printf("Wrote data to %ws\n", output);

    result = 0;

Exit:

    if (request.OutputBuffer != NULL)
    {
        free(request.OutputBuffer);
    }

    return result;
}

///=========================================================================
/// CrashDumpRead()
///
/// <summary>
/// Talks to crashdd.sys driver to read disk using crash dump stack.
/// </summary>
/// <returns>NTSTATUS code</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
ULONG
CrashDumpRead (
    __in PCRASHDD_REQUEST Request,
    __out PULONG BytesRead
    )
{
    HANDLE handle;
    ULONG error;

    //
    // Open handle to our device
    //
    handle = CreateFileW(crashddUserDeviceName,
                         GENERIC_READ | GENERIC_WRITE,
                         NULL,
                         NULL,
                         OPEN_EXISTING,
                         NULL,
                         NULL);

    if (handle == INVALID_HANDLE_VALUE)
    {
        error = GetLastError();
        printf("Failed to open crashdd device:  %08x\n", error);
        goto Exit;
    }    

    //
    // Send IOCTL
    //
    if (!DeviceIoControl(handle,
                         IOCTL_READ_DISK,
                         Request,
                         sizeof(CRASHDD_REQUEST),
                         Request,
                         sizeof(CRASHDD_REQUEST),
                         BytesRead,
                         NULL))
    {
        printf("Failed to send IOCTL %08x:  %08x\n",IOCTL_READ_DISK,GetLastError());
        error = GetLastError();
        goto Exit;
    }

    error = 0;

Exit:

    if (handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(handle);
    }

    return error;
}

///=========================================================================
/// Usage()
///
/// <summary>
/// Prints usage and any error.
/// </summary>
/// <returns>None</returns>
/// <remarks>
/// </remarks>
///========================================================================= 
VOID
Usage (
    INPUT_ERROR_CODE Error
    )
{
    switch(Error)
    {
        case TooFewArguments:
        {
            printf("\n\nError:  Too few arguments.\n");
            break;
        }  
        case TooManyArguments:
        {
            printf("\n\nError:  Too many arguments.\n");
            break;
        }  
        case InvalidDeviceName:
        {
            printf("\n\nError:  Invalid device name.\n");
            break;
        } 
        case InvalidOutputFile:
        {
            printf("\n\nError:  Invalid output file.\n");
            break;
        } 
        case InvalidArgument:
        {
            printf("\n\nError:  Invalid argument.\n");
            break;
        } 
        case InvalidReadOffset:
        {
            printf("\n\nError:  Invalid read offset.\n");
            break;
        } 
        case InvalidReadSize:
        {
            printf("\n\nError:  Invalid read size.\n");
            break;
        } 
        default:
        {
            break;
        }
    }

    printf("\nUsage:  crashdd.exe -if=<input> -of=<output> -offset=<offset> -size=<size>\n");
    printf("\t-if (optional): Input device from which to read data.\n");
    printf("\t-of : File path to write resulting data.\n");
    printf("\t-offset : Byte offset into disk to start reading.\n");
    printf("\t-size : Number of bytes to read (max 64mb).\n");
    printf("\n");
    printf("If no input device is supplied, the first physical drive is used\n (PhysicalDrive0).\n");
    printf("\n");
    printf("The input device MUST be in the format \\??\\<symlink>, where <symlink>\n");
    printf("is the physical drive (PhysicalDriveX) that contains the data to be read.\n");
    printf("Remember that your offset is relative to the starting point of the \n");
    printf("chosen physical disk.  To make the offset relative to the start of a particular\n");
    printf("volume, you must add in the volume's offset.  These offsets are shown in\n");
    printf("the output below.\n");

    printf("\nSearching for drives...\n");

    PrintPhysicalDrives();

    return;
}

VOID
PrintPhysicalDrives (
    VOID
)
{
    ULONG size;
    ULONG result;
    WCHAR logicalDrives[MAX_PATH];
    PWCHAR logicalDrives2;
    PWCHAR linkTarget;
    HANDLE handle;
    VOLUME_DISK_EXTENTS extents;
    VOLUME_DISK_EXTENTS cDrive;
    BOOLEAN success;
    WCHAR driveName[16];
    ULONG i;
    ULONG lastError;

    logicalDrives[0] = L'\0';
    linkTarget = NULL;
    memset(&cDrive, 0, sizeof(cDrive));

    //
    // Get required string length
    // Format of returned string is "A:\\0,B:\\0", etc
    //
    result = GetLogicalDriveStrings(MAX_PATH, logicalDrives);

    if (result == 0)
    {
        printf("Failed to retrieve list of logical drives:  %i\n", GetLastError());
        goto Exit;
    }

    //
    // Print drives
    //
    printf("\n");
    printf("Logical Drive\tPhysical Drive\tPhysical Offset\tLink\n");
    printf("=============\t==============\t===============\t====\n");

    logicalDrives2 = logicalDrives;

    while (*logicalDrives2 != '\0')
    {
        if (wcslen(logicalDrives2) != 3)
        {
            printf("Invalid drive letter:  %ws\n", logicalDrives2);
            goto Exit;
        }

        _snwprintf_s(driveName, 16, 15, L"\\\\.\\%wc:\0", *logicalDrives2);

        //
        // Open the drive
        //   
        handle = CreateFile(driveName,
                            GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL,
                            OPEN_EXISTING,
                            NULL,
                            NULL);

        if (handle == INVALID_HANDLE_VALUE)
        {
            printf("Failed to open drive %ws: %i\n", driveName, GetLastError());
            goto NextDrive;
        }

        //
        // Get the extent structure
        //
        memset(&extents, 0, sizeof(extents));

        success = DeviceIoControl(handle,
                                  IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                  NULL,
                                  0,
                                  &extents,
                                  sizeof(extents),
                                  &result,
                                  NULL);
        
        //
        // Resolve its symbolic link
        //
        _snwprintf_s(driveName, 16, 15, L"%wc:", *logicalDrives2);
        linkTarget = NULL;
        size = 0;

        result = QueryDosDevice(driveName, linkTarget, size);
        lastError = GetLastError();

        if (result == 0)
        {
            while (lastError == ERROR_INSUFFICIENT_BUFFER)
            {
                size += MAX_PATH;
                linkTarget = (PWCHAR)calloc(1, size);
                result = QueryDosDevice(driveName, linkTarget, size);
                lastError = GetLastError();

                if (result != 0)
                {
                    break;
                }

                free(linkTarget);
                linkTarget = NULL;
            }
        }

        //
        // if "C" drive, save for suggested output
        //
        if (extents.NumberOfDiskExtents > 0)
        {
            if (*logicalDrives2 == L'c' || *logicalDrives2 == L'C')
            {
                memcpy(&cDrive, &extents, sizeof(cDrive));
            }
        }

        //
        // Print the information
        //
        printf("%ws\t", driveName);

        if (extents.NumberOfDiskExtents == 0)
        {
            printf("\t--unknown--\t--unknown--\t%ws\n",
                  (linkTarget == NULL) ? L"--unknown--" : linkTarget);
        }
        else
        {
            for (i = 0; i < extents.NumberOfDiskExtents; i++)
            {
                printf("\tPhysicalDrive%lu\t%I64u\t%ws\n",
                       extents.Extents[i].DiskNumber,
                       extents.Extents[i].StartingOffset.QuadPart,
                       (linkTarget == NULL) ? L"--unknown--" : linkTarget);
            }
        }

        //
        // Go to next drive
        //
NextDrive:

        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }

        if (linkTarget != NULL)
        {
            free(linkTarget);
            linkTarget = NULL;
        }

        logicalDrives2 += wcslen(logicalDrives2) + 1;
    }

    if (cDrive.NumberOfDiskExtents == 1)
    {
        printf("\nYour \"C:\" drive is located at offset %I64u on the first "\
               "physical \ndisk drive.  It does not span multiple physical "\
               "disks.  \nYou can specify \\??\\PhysicalDrive0 and add %I64u "\
               "to read data \non the C drive.\n",
               cDrive.Extents[0].StartingOffset.QuadPart,
               cDrive.Extents[0].StartingOffset.QuadPart);
    }
    else if (cDrive.NumberOfDiskExtents > 1)
    {
        printf("\nYour \"C:\" drive is located at offset %I64u of the first "\
               "physical \ndisk drive and spans a total of %lu physical "\
               "disks.  \nYou can specify \\??\\PhysicalDrive0 and add %I64u "\
               "to read data \non the C drive.\n",
               cDrive.Extents[0].StartingOffset.QuadPart,
               cDrive.NumberOfDiskExtents,
               cDrive.Extents[0].StartingOffset.QuadPart);
    }

Exit:

    return;
}