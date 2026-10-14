/* Safe twin for the file-level device ACL rule. */
#include <ntddk.h>
#include <wdmsec.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PDEVICE_OBJECT dev;
    /* ok-file: win.insecure-device-acl */
    return IoCreateDeviceSecure(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &dev);
}
