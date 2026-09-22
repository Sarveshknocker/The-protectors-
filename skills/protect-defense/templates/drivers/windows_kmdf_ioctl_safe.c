/*
 * Reference pattern: hardened KMDF IOCTL handling (Windows 10 2004+ for ExAllocatePool2).
 * - METHOD_BUFFERED + explicit access rights in CTL_CODE
 * - device ACL restricted to SYSTEM and Administrators
 * - minimum buffer sizes enforced by WdfRequestRetrieve*Buffer
 * - every input field validated; unknown codes rejected
 * - ExAllocatePool2 (zeroed, non-executable, HVCI compatible)
 * Adapt names; keep the patterns. Run SDV + CodeQL + Driver Verifier before signing.
 */
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

#define DEMO_NAME_MAX 32
#define DEMO_POOL_TAG 'omeD'

#define IOCTL_DEMO_SET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_DEMO_GET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef struct _DEMO_SET_REQ {
    ULONG Id;
    ULONG Len;                       /* bytes used in Name */
    CHAR  Name[DEMO_NAME_MAX];
} DEMO_SET_REQ;

typedef struct _DEMO_GET_RESP {
    ULONG Id;
    ULONG Len;
    CHAR  Name[DEMO_NAME_MAX];
} DEMO_GET_RESP;

typedef struct _DEVICE_CONTEXT {
    WDFWAITLOCK   Lock;
    DEMO_GET_RESP State;             /* protected by Lock */
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD DemoEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL DemoEvtIoDeviceControl;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    WDF_DRIVER_CONFIG_INIT(&config, DemoEvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}

NTSTATUS DemoEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    NTSTATUS status;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES attrs;
    WDF_IO_QUEUE_CONFIG queueConfig;
    PDEVICE_CONTEXT ctx;
    UNREFERENCED_PARAMETER(Driver);

    /* Only SYSTEM and Administrators may open the device. */
    status = WdfDeviceInitAssignSDDL(DeviceInit, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (!NT_SUCCESS(status)) return status;
    WdfDeviceInitSetCharacteristics(DeviceInit, FILE_DEVICE_SECURE_OPEN, TRUE);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, DEVICE_CONTEXT);
    status = WdfDeviceCreate(&DeviceInit, &attrs, &device);
    if (!NT_SUCCESS(status)) return status;

    ctx = GetDeviceContext(device);
    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &ctx->Lock);
    if (!NT_SUCCESS(status)) return status;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = DemoEvtIoDeviceControl;
    return WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
}

VOID DemoEvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, _In_ size_t OutputBufferLength,
                            _In_ size_t InputBufferLength, _In_ ULONG IoControlCode)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t info = 0;
    PDEVICE_CONTEXT ctx = GetDeviceContext(WdfIoQueueGetDevice(Queue));
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode) {
    case IOCTL_DEMO_SET: {
        DEMO_SET_REQ *req;
        /* Fails with STATUS_BUFFER_TOO_SMALL if the caller sent less than sizeof(*req). */
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*req), (PVOID *)&req, NULL);
        if (!NT_SUCCESS(status)) break;
        if (req->Len > DEMO_NAME_MAX) { status = STATUS_INVALID_PARAMETER; break; }

        WdfWaitLockAcquire(ctx->Lock, NULL);
        RtlZeroMemory(&ctx->State, sizeof(ctx->State));
        ctx->State.Id = req->Id;
        ctx->State.Len = req->Len;
        RtlCopyMemory(ctx->State.Name, req->Name, req->Len);
        WdfWaitLockRelease(ctx->Lock);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_DEMO_GET: {
        DEMO_GET_RESP *resp;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(*resp), (PVOID *)&resp, NULL);
        if (!NT_SUCCESS(status)) break;

        WdfWaitLockAcquire(ctx->Lock, NULL);
        *resp = ctx->State;          /* whole struct copied; State is always zero-initialised */
        WdfWaitLockRelease(ctx->Lock);
        info = sizeof(*resp);
        status = STATUS_SUCCESS;
        break;
    }
    default:
        break;                       /* unknown codes rejected */
    }
    WdfRequestCompleteWithInformation(Request, status, info);
}

/* Heap allocations, when needed: zeroed + non-executable.
 *   PVOID p = ExAllocatePool2(POOL_FLAG_PAGED, size, DEMO_POOL_TAG);
 *   if (p == NULL) return STATUS_INSUFFICIENT_RESOURCES;
 *   ... ExFreePoolWithTag(p, DEMO_POOL_TAG);
 */
