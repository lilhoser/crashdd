
#pragma once

#define MAX_READ_SIZE (0xffff * 0x400) //64mb
#define FILE_DEVICE_CRASHDD 0x0c1a51dd
#define IOCTL_READ_DISK (ULONG)CTL_CODE(FILE_DEVICE_CRASHDD, \
                                        0x55, \
                                        METHOD_BUFFERED, \
                                        FILE_ANY_ACCESS)

static const WCHAR crashddUserDeviceName[]  = L"\\\\.\\crashdd";
static const WCHAR crashddDeviceName[]  = L"\\Device\\crashdd";

typedef struct _CRASHDD_REQUEST
{
    ULONGLONG Offset;
    ULONG Size;
    UNICODE_STRING DeviceName;
    PVOID OutputBuffer;
    ULONG BytesRead;
} CRASHDD_REQUEST, *PCRASHDD_REQUEST;