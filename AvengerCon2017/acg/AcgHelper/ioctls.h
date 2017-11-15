#pragma once

#ifdef USERMODE
#include <winioctl.h>
#else
#include <ntifs.h>
#endif

#define IOCTL_DISABLE_ACG               CTL_CODE(FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Expects ULONG Pid in SystemBuffer

#define IOCTL_ENABLE_THREAD_OPT_OUT     CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Expects ULONG Tid in SystemBuffer

#define IOCTL_PROTECT_MEMORY_RWX_PTE    CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Expects PVOID Address in SystemBuffer. Protects a single page as RWX.

#define IOCTL_PROTECT_MEMORY            CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct _PROTECT_MEMORY {
    HANDLE ProcessHandle;
    PVOID Address;
    SIZE_T RegionSize;
    ULONG Protect;
} PROTECT_MEMORY, *PPROTECT_MEMORY;

#define IOCTL_ALLOCATE_MEMORY           CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct _ALLOCATE_MEMORY {
    HANDLE ProcessHandle;
    SIZE_T RegionSize;
    ULONG Protect;
} ALLOCATE_MEMORY, *PALLOCATE_MEMORY;

#define IOCTL_WRITE_MEMORY_MDL          CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY_TOGGLE_WP    CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct _WRITE_MEMORY {
    PVOID Address;
    PVOID Buffer;
    ULONG Size;
} WRITE_MEMORY, *PWRITE_MEMORY;

// Union so we can reference all arguments from a single pointer without lots of casting
typedef union _IOCTL_ARGS {
    ULONG pid;
    ULONG tid;
    PVOID address;
    PROTECT_MEMORY protect;
    ALLOCATE_MEMORY allocate;
    WRITE_MEMORY write;
} IOCTL_ARGS, *PIOCTL_ARGS;