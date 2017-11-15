#include <ntifs.h>
#include "ioctls.h"

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\AcgHelper");
UNICODE_STRING DEVICE_SYMLINK = RTL_CONSTANT_STRING(L"\\DosDevices\\AcgHelper");

#define CR0_WRITE_PROTECT_MASK  0x10000

// Only for Windows 10 1709 Fall Creators Update!
#define EPROCESS_MITIGATION_FLAGS_VALUES_OFFSET     0x828
#define EPROCESS_DISABLE_DYNAMIC_CODE_MASK          0x100
#define ETHREAD_CROSS_THREAD_FLAGS_OFFSET           0x6d0
#define ETHREAD_DISABLE_DYNAMIC_CODE_OPT_OUT_MASK   0x40000

// Only on x64!
#pragma warning(push)
#pragma warning(disable:4214)
#define _HARDWARE_PTE_WORKING_SET_BITS  11
typedef struct _HARDWARE_PTE {
    ULONG64 Valid : 1;
    ULONG64 Write : 1;
    ULONG64 Owner : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Accessed : 1;
    ULONG64 Dirty : 1;
    ULONG64 LargePage : 1;
    ULONG64 Global : 1;
    ULONG64 CopyOnWrite : 1;          // software field
    ULONG64 Prototype : 1;            // software field
    ULONG64 reserved0 : 1;            // software field
    ULONG64 PageFrameNumber : 28;
    ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
    ULONG64 SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
    ULONG64 NoExecute : 1;
} HARDWARE_PTE, *PHARDWARE_PTE;
#pragma warning(pop)

static HARDWARE_PTE ReadPhysicalAddress64(ULONG64 Address)
{
    HARDWARE_PTE pte = { 0 };
    PHYSICAL_ADDRESS paddr;
    paddr.QuadPart = Address;
    PVOID vaddr = MmMapIoSpace(paddr, sizeof(pte), MmNonCached);
    if (vaddr == NULL) {
        return pte;   // We'll just accept the fact that we failed and crash because I'm lazy.
                      // This would normally only fail under low-resource conditions.
    }

    memcpy(&pte, vaddr, sizeof(pte));
    MmUnmapIoSpace(vaddr, sizeof(ULONG64));
    return pte;
}

static VOID WritePhysicalAddress64(ULONG64 Address, HARDWARE_PTE Value)
{
    PHYSICAL_ADDRESS paddr;
    paddr.QuadPart = Address;
    PVOID vaddr = MmMapIoSpace(paddr, sizeof(ULONG64), MmNonCached);
    if (vaddr == NULL) {
        return;
    }

    memcpy(vaddr, &Value, sizeof(Value));
    MmUnmapIoSpace(vaddr, sizeof(ULONG64));
}

// SUCCESS - Permanently turn off EPROCESS.MitigationFlagsValues.DisableDynamicCode
NTSTATUS DisableProcessMitigation(ULONG pid)
{
    PEPROCESS Process = NULL;
    NTSTATUS retval = PsLookupProcessByProcessId((HANDLE)pid, &Process);
    if (!NT_SUCCESS(retval)) {
        DbgPrint("PsLookupProcessByProcessId: %08x\n", retval);
        return retval;
    }

    PULONG MitigationFlagsValues = (PULONG)(((ULONG_PTR)Process) + EPROCESS_MITIGATION_FLAGS_VALUES_OFFSET);
    ClearFlag(*MitigationFlagsValues, EPROCESS_DISABLE_DYNAMIC_CODE_MASK);

    return STATUS_SUCCESS;
}

// SUCCESS - Permanently enable ETHREAD.DisableDynamicCodeOptOut (without setting EPROCESS.MitigationFlagsValues.DisableDynamicCodeAllowOptOut)
NTSTATUS EnableThreadOptOut(ULONG tid)
{
    PETHREAD Thread = NULL;
    NTSTATUS retval = PsLookupThreadByThreadId((HANDLE)tid, &Thread);
    if (!NT_SUCCESS(retval)) {
        DbgPrint("PsLookupThreadByThreadId: %08x\n", retval);
        return retval;
    }

    PULONG CrossThreadFlags = (PULONG)(((ULONG_PTR)Thread) + ETHREAD_CROSS_THREAD_FLAGS_OFFSET);
    SetFlag(*CrossThreadFlags, ETHREAD_DISABLE_DYNAMIC_CODE_OPT_OUT_MASK);

    return STATUS_SUCCESS;
}

// FAIL - ZwAllocateVirtualMemory fails with STATUS_DYNAMIC_CODE_BLOCKED
NTSTATUS AllocateVirtualMemory(HANDLE Process, SIZE_T RegionSize, ULONG Protect, __out PVOID *Address)
{
    NTSTATUS retval = ZwAllocateVirtualMemory(Process, Address, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, Protect);
    if (!NT_SUCCESS(retval)) {
        DbgPrint("ZwAllocateVirtualMemory: %08x\n", retval);
        return retval;
    }

    return STATUS_SUCCESS;
}

// SUCCESS - We're remapping the physical pages and we can therefore write to them.
NTSTATUS WriteVirtualMemoryMdl(PVOID Address, PVOID Buffer, ULONG Size)
{
    // It wouldn't be difficult to write to an arbitrary process by attaching to it.
    // Given the PID, get a pointer to the EPROCESS and use KeStackAttachProcess before probing pages.

    PMDL mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    PVOID SystemAddr = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (SystemAddr == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Buffer points to userspace so we have to use __try/__except
    __try {
        memcpy(SystemAddr, Buffer, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    // Clean up
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}

// SUCCESS - Have to deal with PatchGuard though
NTSTATUS WriteVirtualMemoryToggleWp(PVOID Address, PVOID Buffer, ULONG Size)
{
    ULONGLONG cr0 = __readcr0();
    ULONGLONG cr0new = cr0;
    ClearFlag(cr0new, CR0_WRITE_PROTECT_MASK);
    
    __try {
        __writecr0(cr0new);
        memcpy(Address, Buffer, Size);
        __writecr0(cr0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        __writecr0(cr0);
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

// SUCCESS - Since we're following physical address we don't have to worry about KASLR.
NTSTATUS ProtectVirtualMemoryRwxPte(PVOID Address)
{
    ULONG64 vaddr = (ULONG64)Address;

    // Read the pml4 entry (Page Map Level 4 Entry)
    ULONG64 cr3 = __readcr3();
    ULONG offset = ((vaddr >> 39) & 0x1ff) * 8;
    HARDWARE_PTE pte = ReadPhysicalAddress64(cr3 + offset);
    ULONG64 pml3base = pte.PageFrameNumber << 12;

    // Read the pml3 entry (Page Directory Pointer Table Entry)
    offset = ((vaddr >> 30) & 0x1ff) * 8;
    pte = ReadPhysicalAddress64(pml3base + offset);
    ULONG64 pml2base = pte.PageFrameNumber << 12;

    // Read the pml2 entry (Page Directory Entry)
    offset = ((vaddr >> 21) & 0x1ff) * 8;
    pte = ReadPhysicalAddress64(pml2base + offset);
    ULONG64 pml1base = pte.PageFrameNumber << 12;

    // Read the pml1 entry (Page Table Entry)
    offset = ((vaddr >> 12) & 0x1ff) * 8;
    pte = ReadPhysicalAddress64(pml1base + offset);
    
    // Disable NX bit
    pte.NoExecute = FALSE;
    
    // Write back the PTE
    WritePhysicalAddress64(pml1base + offset, pte);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS retval = STATUS_SUCCESS;
    PIO_STACK_LOCATION Iosl = IoGetCurrentIrpStackLocation(Irp);
    PIOCTL_ARGS args = (PIOCTL_ARGS)Irp->AssociatedIrp.SystemBuffer;
    PVOID BaseAddress = NULL;

    switch (Iosl->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_DISABLE_ACG:
        retval = DisableProcessMitigation(args->pid);
        break;
    case IOCTL_ENABLE_THREAD_OPT_OUT:
        retval = EnableThreadOptOut(args->tid);
        break;
    case IOCTL_PROTECT_MEMORY:
        retval = STATUS_NOT_IMPLEMENTED;
        break;
    case IOCTL_ALLOCATE_MEMORY:
        retval = AllocateVirtualMemory(args->allocate.ProcessHandle, args->allocate.RegionSize, args->allocate.Protect, &BaseAddress);
        break;
    case IOCTL_WRITE_MEMORY_MDL:
        retval = WriteVirtualMemoryMdl(args->write.Address, args->write.Buffer, args->write.Size);
        break;
    case IOCTL_WRITE_MEMORY_TOGGLE_WP:
        retval = WriteVirtualMemoryToggleWp(args->write.Address, args->write.Buffer, args->write.Size);
        break;
    case IOCTL_PROTECT_MEMORY_RWX_PTE:
        retval = ProtectVirtualMemoryRwxPte(args->address);
        break;
    default:
        retval = STATUS_NOT_IMPLEMENTED;
        break;
    }

    Irp->IoStatus.Status = retval;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return retval;
}

NTSTATUS DispatchCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(
    PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&DEVICE_SYMLINK);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS retval = IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(retval)) {
        return retval;
    }

    retval = IoCreateSymbolicLink(&DEVICE_SYMLINK, &DEVICE_NAME);
    if (!NT_SUCCESS(retval)) {
        IoDeleteDevice(DeviceObject);
        return retval;
    }
    
    return STATUS_SUCCESS;
}