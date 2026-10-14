/* Rule corpus (Windows driver). */
#include <ntddk.h>

/* ruleid: win.method-neither */
#define IOCTL_DEMO_RAW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
/* ok: win.method-neither */
#define IOCTL_DEMO_OK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PDEVICE_OBJECT dev;
    /* ruleid: win.insecure-device-acl */
    IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    /* ruleid: win.deprecated-pool */
    PVOID a = ExAllocatePoolWithTag(NonPagedPool, 64, 'omed');
    /* ok: win.deprecated-pool */
    PVOID b = ExAllocatePool2(POOL_FLAG_NON_PAGED, 64, 'omed');
    /* ruleid: win.dangerous-primitive */
    PVOID m = MmMapIoSpace(addr, len, MmNonCached);
    /* ok: win.dangerous-primitive */
    PVOID r = MmGetSystemRoutineAddress(&routine);
    return STATUS_SUCCESS;
}
