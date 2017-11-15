#include <windows.h>
#include <stdio.h>

#define USERMODE
#include "ioctls.h"

#define DEVICE_NAME "\\\\.\\AcgHelper"
#define PAGE_SIZE   4096

// UTILITY Functions -----------------------------------------------------------

static void ProhibitDynamicCode()
{
    BOOL success;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = { 0 };
    policy.ProhibitDynamicCode = 1;
    //PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
    success = SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy));
    if (!success) {
        printf("SetProcessMitigationPolicy: %lu\n", GetLastError());
    }
}

// Enable ACG for child processes
static int ProhibitDynamicCodeChildProcesses()
{
    ProhibitDynamicCode();

    LPPROC_THREAD_ATTRIBUTE_LIST attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2048);
    SIZE_T size = 2048;
    BOOL success = InitializeProcThreadAttributeList(attrs, 1, 0, &size);
    if (!success) {
        printf("InitializeProcThreadAttributeList: %lu\n", GetLastError());
        return 1;
    }

    SIZE_T attrValue = PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    success = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &attrValue, 4, NULL, NULL);
    if (!success) {
        printf("UpdateProcThreadAttribute: %lu\n", GetLastError());
        return 1;
    }

    return 0;
}

// Stub function meant to be overwritten with ACG on to demonstrate that we can mutate code pages
static int StubFunction()
{
    printf("Stub function unchanged!\n");
    return 0;
}

// USERMODE Tests --------------------------------------------------------------

// FAILS with ERROR_ACCESS_DENIED
int UserDisableAcg()
{
    BOOL success;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = { 0 };
    success = SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy));
    if (!success) {
        printf("SetProcessMitigationPolicy2: %lu\n", GetLastError());
        return 1;
    }

    return 0;
}

// FAIL - VirtualProtect fails with error 1655
int TestVirtualProtectRwx()
{
    DWORD oldProtect;
    BOOL success = VirtualProtect(StubFunction, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!success) {
        printf("VirtualProtect: %lu\n", GetLastError());
        return 1;
    }

    printf("success\n");
    return 0;
}

// FAIL - VirtualAlloc fails with error 1655
int TestVirtualAllocRwx()
{
    PVOID addr = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NULL == addr) {
        printf("VirtualAlloc: %lu\n", GetLastError());
        return 1;
    }

    printf("success\n");
    return 0;
}

// FAIL - VirtualProtect fails with error 1655
int TestVirtualAllocRwAndChangeRx()
{
    PVOID addr = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == addr) {
        printf("VirtualAlloc: %lu\n", GetLastError());
        return 1;
    }

    memset(addr, 'a', PAGE_SIZE);

    DWORD oldProtect = 0;
    BOOL success = VirtualProtect(addr, PAGE_SIZE, PAGE_EXECUTE, &oldProtect);
    if (!success) {
        printf("VirtualProtect: %lu\n", GetLastError());
        return 1;
    }

    printf("success\n");
    return 0;
}

// FAIL - MapViewOfFile fails with error 1655
int TestRwxMappingRwx()
{
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, PAGE_SIZE, NULL);
    if (NULL == hMapping) {
        printf("CreateFileMapping: %lu\n", GetLastError());
        return 1;
    }

    PVOID addr = MapViewOfFile(hMapping, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, PAGE_SIZE);
    if (NULL == addr) {
        printf("MapViewOfFile: %lu\n", GetLastError());
        return 1;
    }
    memset(addr, 'a', PAGE_SIZE);

    printf("success\n");
    return 0;
}

// FAIL - Second MapViewOfFile fails with error 1655
int TestRwxMappingRw()
{
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, PAGE_SIZE, NULL);
    if (NULL == hMapping) {
        printf("CreateFileMapping: %lu\n", GetLastError());
        return 1;
    }

    PVOID addr = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, PAGE_SIZE);
    if (NULL == addr) {
        printf("MapViewOfFile: %lu\n", GetLastError());
        return 1;
    }
    memset(addr, 'a', PAGE_SIZE);
    strcpy((char *)addr, "\xeb\xfe");

    PVOID addr2 = MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, PAGE_SIZE);
    if (NULL == addr2) {
        printf("MapViewOfFile2: %lu\n", GetLastError());
        return 1;
    }

    printf("Entering infinite loop - success if there's a hang.\n");
    ((void(*)())addr2)();
    return 0;
}

// FAIL - Second MapViewOfFile fails with error 87 (invalid parameter) since the file mapping was originally created non-execute
int TestDualNamedMapping()
{
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, PAGE_SIZE, "Global\\testfile");
    if (NULL == hMapping) {
        printf("CreateFileMapping: %lu\n", GetLastError());
        return 1;
    }

    PVOID addr = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, PAGE_SIZE);
    if (NULL == addr) {
        printf("MapViewOfFile: %lu\n", GetLastError());
        return 1;
    }
    memset(addr, 'a', PAGE_SIZE);
    strcpy((char *)addr, "\xeb\xfe");
    UnmapViewOfFile(addr);

    HANDLE hMapping2 = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READ, 0, PAGE_SIZE, "Global\\testfile");
    if (NULL == hMapping) {
        printf("CreateFileMapping2: %lu\n", GetLastError());
        return 1;
    }

    PVOID addr2 = MapViewOfFile(hMapping2, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, PAGE_SIZE);
    if (NULL == addr2) {
        printf("MapViewOfFile2: %lu\n", GetLastError());
        return 1;
    }

    printf("Entering infinite loop - success if there's a hang.\n");
    ((void(*)())addr2)();
    return 0;
}

// FAIL - Second MapViewOfFile fails with error 1655
int TestDualNamedMappingRwx()
{
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, PAGE_SIZE, "Global\\testfile");
    if (NULL == hMapping) {
        printf("CreateFileMapping: %lu\n", GetLastError());
        return 1;
    }

    PVOID addr = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, PAGE_SIZE);
    if (NULL == addr) {
        printf("MapViewOfFile: %lu\n", GetLastError());
        return 1;
    }
    memset(addr, 'a', PAGE_SIZE);
    strcpy((char *)addr, "\xeb\xfe");
    UnmapViewOfFile(addr);

    HANDLE hMapping2 = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READ, 0, PAGE_SIZE, "Global\\testfile");
    if (NULL == hMapping) {
        printf("CreateFileMapping2: %lu\n", GetLastError());
        return 1;
    }

    PVOID addr2 = MapViewOfFile(hMapping2, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, PAGE_SIZE);
    if (NULL == addr2) {
        printf("MapViewOfFile2: %lu\n", GetLastError());
        return 1;
    }

    printf("Entering infinite loop - success if there's a hang.\n");
    ((void(*)())addr2)();
    return 0;
}

// FAIL - MapViewOfFile fails with error 1655
int TestMapFromDisk()
{
    // Drop infinite loop shellcode to disk
    CHAR buf[PAGE_SIZE] = { '\xeb', '\xfe' };
    HANDLE hFile = CreateFileA("testfile", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD cbWritten = 0;
    WriteFile(hFile, buf, PAGE_SIZE, &cbWritten, NULL);
    CloseHandle(hFile);

    // Create a section backed by the file
    hFile = CreateFileA("testfile", GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_EXECUTE_READ, 0, 0, NULL);
    if (hMapping == NULL) {
        printf("CreateFileMapping: %lu\n", GetLastError());
        return 1;
    }

    // Map the section into our address space
    PVOID addr = MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, PAGE_SIZE);
    if (addr == NULL) {
        printf("MapViewOfFile: %lu\n", GetLastError());
        return 1;
    }

    // HANG!
    printf("Entering infinite loop - success if there's a hang.\n");
    ((void(*)())addr)();
    return 0;
}

// KERNELMODE Tests ------------------------------------------------------------

// SUCCESS
int KernelDisableAcg()
{
    // Disable ACG by flipping the "MitigationFlags->DisableDynamicCode" bit in our EPROCESS from kernel mode
    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFileA: %lu\n", GetLastError());
        return -1;
    }

    ULONG pid = GetCurrentProcessId();
    ULONG nBytesReturned = 0;
    BOOLEAN success = DeviceIoControl(hDevice, IOCTL_DISABLE_ACG, &pid, sizeof(pid), NULL, 0, &nBytesReturned, NULL);
    if (!success || GetLastError()) {
        printf("DeviceIoControl: %lu\n", GetLastError());
        return -1;
    }

    return 0;
}

// SUCCESS
int KernelEnableThreadOptOut()
{
    // Enable thread opt-out from kernel mode by setting "DisableDynamicCodeOptOut" field in our ETHREAD.
    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFileA: %lu\n", GetLastError());
        return -1;
    }

    ULONG tid = GetCurrentThreadId();
    ULONG nBytesReturned = 0;
    BOOLEAN success = DeviceIoControl(hDevice, IOCTL_ENABLE_THREAD_OPT_OUT, &tid, sizeof(tid), NULL, 0, &nBytesReturned, NULL);
    if (!success || GetLastError()) {
        printf("DeviceIoControl: %lu\n", GetLastError());
        return -1;
    }

    return 0;
}

// UNKNOWN - not tested, but in theory you could find the address of MmProtectVirtualMemory, Set PreviousMode to KernelMode,
// set DisableDynamicCodeOptOut in a system thread, and use that thread to call MmProtectVirtualMemory.
int TestKernelProtectMemory()
{
    // Try to change memory permissions for a RW page to RWX from kernel mode
    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFileA: %lu\n", GetLastError());
        return -1;
    }

    PVOID addr = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!addr) {
        printf("VirtualAlloc: %lu\n", GetLastError());
        return -1;
    }
    memset(addr, 0, PAGE_SIZE);
    strcpy((char *)addr, "\xeb\xfe");

    PROTECT_MEMORY args = { 0 };
    args.ProcessHandle = GetCurrentProcess();
    args.Address = addr;
    args.RegionSize = PAGE_SIZE;
    args.Protect = PAGE_EXECUTE_READWRITE;
    ULONG nBytesReturned = 0;
    BOOLEAN success = DeviceIoControl(hDevice, IOCTL_PROTECT_MEMORY, &args, sizeof(args), NULL, 0, &nBytesReturned, NULL);
    printf("%d\n", GetLastError());
    if (!success || GetLastError()) {
        printf("DeviceIoControl: %lu\n", GetLastError());
        return -1;
    }

    printf("Entering infinite loop - success if there's a hang.\n");
    ((void(*)())addr)();
    return 0;
}

// FAIL - ZwAllocateVirtualMemory fails with error 1655
int TestKernelAllocateMemory()
{
    // Try to allocate RWX memory from kernel mode
    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFileA: %lu\n", GetLastError());
        return -1;
    }

    ALLOCATE_MEMORY args;
    args.ProcessHandle = GetCurrentProcess();
    args.RegionSize = PAGE_SIZE;
    args.Protect = PAGE_EXECUTE_READWRITE;
    ULONG nBytesReturned = 0;
    BOOLEAN success = DeviceIoControl(hDevice, IOCTL_ALLOCATE_MEMORY, &args, sizeof(args), NULL, 0, &nBytesReturned, NULL);
    if (!success || GetLastError()) {
        printf("DeviceIoControl: %lu\n", GetLastError());
        return -1;
    }

    return 0;
}

// SUCCESS (limited) - We can only write to existing executable pages. We can't allocate new executable ones.
int TestKernelWriteMemoryMdl()
{
    // Remap the StubFunction physical page into kernelmode virtual address space and overwrite with shellcode.
    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFileA: %lu\n", GetLastError());
        return -1;
    }

    /* VirtualAlloc(..., PAGE_EXECUTE_READ) fails with ACG on
    PVOID addr = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!addr) {
        printf("VirtualAlloc: %lu\n", GetLastError());
        return -1;
    }
    */

    // Validate StubFunction original functionality
    printf("Testing StubFunction - should not hang\n");
    StubFunction();

    WRITE_MEMORY args;
    args.Address = StubFunction;
    args.Buffer = "\xeb\xfe";
    args.Size = 2;
    ULONG nBytesReturned = 0;
    BOOLEAN success = DeviceIoControl(hDevice, IOCTL_WRITE_MEMORY_MDL, &args, sizeof(args), NULL, 0, &nBytesReturned, NULL);
    if (!success || GetLastError()) {
        printf("DeviceIoControl: %lu\n", GetLastError());
        return -1;
    }

    // Should have overwritten StubFunction with an infinite loop
    printf("Entering infinite loop - success if there's a hang.\n");
    StubFunction();
    return 0;
}

// SUCCESS (limited) - We can only write to existing executable pages. We can't allocate new executable ones.
int TestKernelWriteMemoryToggleWp()
{
    // Toggle the cr0 WriteProtect bit and overwrite StubFunction with shellcode
    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFileA: %lu\n", GetLastError());
        return -1;
    }

    /* VirtualAlloc(..., PAGE_EXECUTE_READ) fails with ACG on
    PVOID addr = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!addr) {
    printf("VirtualAlloc: %lu\n", GetLastError());
    return -1;
    }
    */

    // Validate StubFunction original functionality
    printf("Testing StubFunction - should not hang\n");
    StubFunction();

    WRITE_MEMORY args;
    args.Address = StubFunction;
    args.Buffer = "\xeb\xfe";
    args.Size = 2;
    ULONG nBytesReturned = 0;
    BOOLEAN success = DeviceIoControl(hDevice, IOCTL_WRITE_MEMORY_TOGGLE_WP, &args, sizeof(args), NULL, 0, &nBytesReturned, NULL);
    if (!success || GetLastError()) {
        printf("DeviceIoControl: %lu\n", GetLastError());
        return -1;
    }

    // Should have overwritten StubFunction with an infinite loop
    printf("Entering infinite loop - success if there's a hang.\n");
    StubFunction();
    return 0;
}

// SUCCESS (limited) - We can only write to existing executable pages. We can't allocate new executable ones.
int TestKernelProtectMemoryRwxPte()
{
    // Allocate RW memory in usermode, write shellcode to it, then flip the NX bit on the PTE in kernelmode
    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("CreateFileA: %lu\n", GetLastError());
        return -1;
    }
    printf("[*] Opened driver handle: 0x%p\n", hDevice);

    char *addr = (char *)VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!addr) {
        printf("VirtualAlloc: %lu\n", GetLastError());
        return -1;
    }
    printf("[*] Allocated RW Page: 0x%p\n", addr);
    memset(addr, 0, PAGE_SIZE);
    strcpy((char *)addr, "\xeb\xfe");
    printf("[*] Wrote Contents: %02hhx%02hhx%02hhx%02hhx\n", addr[0], addr[1], addr[2], addr[3]);    
    
    __try {
        printf("[*] Calling 0x%p - should cause a fault\n", addr);
        ((void(*)())addr)();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[+] Fault caught! 0x%p is not executable!\n", addr);
    }

    ULONG nBytesReturned = 0;
    BOOLEAN success = DeviceIoControl(hDevice, IOCTL_PROTECT_MEMORY_RWX_PTE, &addr, sizeof(addr), NULL, 0, &nBytesReturned, NULL);
    if (!success || GetLastError()) {
        printf("DeviceIoControl: %lu\n", GetLastError());
        return -1;
    }
    printf("[*] Updated allocated page permissions to RWX\n");

    // Should have overwritten StubFunction with an infinite loop
    printf("[*] Calling 0x%p - should hang on success\n", addr);
    ((void(*)())addr)();
    return 0;
}

// MAIN ------------------------------------------------------------------------

int main(int argc, char **argv)
{
    printf("%x:%x\n", GetCurrentProcessId(), GetCurrentThreadId());
    ProhibitDynamicCode();
    
    // Insert test code here
    TestKernelProtectMemoryRwxPte();

    return 0;
}