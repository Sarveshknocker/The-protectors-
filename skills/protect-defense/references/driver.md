# Driver / kernel-code playbook (Linux modules, Windows KMDF/WDM, macOS DriverKit, user-space USB/HID)

Kernel bugs are privilege escalation: any user who can open the device can attack the whole OS. "Bring your own vulnerable driver" attacks abuse signed-but-sloppy drivers, so vendors are now blocked by Microsoft's vulnerable driver blocklist.

## Threats
Arbitrary kernel read/write via IOCTLs, unchecked user pointers and lengths, integer overflows in size calculations, info leaks (uninitialised stack/heap copied to user space), TOCTOU on user memory (double fetch), use-after-free/race conditions on shared state, over-permissive device ACLs, exposed physical-memory/MSR/port-I/O primitives.

## Linux kernel modules — mandatory
1. **User memory**: only `copy_from_user`/`copy_to_user`/`get_user`/`put_user`, **always check the return value** (`return -EFAULT`), validate user-supplied lengths against destination sizes *before* copying, copy once (no double fetch), use `memdup_user` for variable buffers with an upper bound.
2. **Sizes**: `kmalloc_array`, `kcalloc`, `array_size()`, `struct_size()`; `check_*_overflow()` helpers.
3. **Info leaks**: zero structs before filling (`= {}` / `memset`) and before `copy_to_user`; use `kzalloc`.
4. **Access control**: `capable(CAP_…)` (narrowest capability) on privileged ioctls; device node mode via udev rules (not 0666); validate `cmd` with `_IOC_TYPE/_IOC_NR` and reject unknown commands with `-ENOTTY`.
5. **Concurrency**: locks around shared state, refcounting (`kref`) for objects reachable from file descriptors; release paths safe against concurrent ioctls.
6. **Strings**: `strscpy`, `kstrto*()`; never `sprintf` into fixed buffers (use `scnprintf`/`sysfs_emit`).
7. Reference implementation: `templates/drivers/linux_ioctl_safe.c`.
8. **Tooling**: `sparse` (`make C=1`), `smatch`, `coccinelle` (`make coccicheck`), `checkpatch.pl --strict`; test with KASAN, UBSAN, KCSAN, lockdep; fuzz with **syzkaller** (describe the ioctls in syzlang).
9. **Signing**: sign modules (`CONFIG_MODULE_SIG_FORCE` on target systems), support Secure Boot / lockdown mode.

## Windows drivers — mandatory
1. **Prefer KMDF** (or UMDF when kernel mode isn't needed — a user-mode driver bug can't crash or own the kernel).
2. **IOCTLs**: `METHOD_BUFFERED` (or `METHOD_IN/OUT_DIRECT`); retrieve buffers with `WdfRequestRetrieveInputBuffer(request, sizeof(expected), …)` to enforce minimum sizes; validate every field; reject unknown codes with `STATUS_INVALID_DEVICE_REQUEST`. If `METHOD_NEITHER` is unavoidable: `ProbeForRead/ProbeForWrite` inside `__try/__except`, capture values into kernel memory once.
3. **Device security**: `WdfDeviceInitAssignSDDL(… SDDL_DEVOBJ_SYS_ALL_ADM_ALL …)` or `IoCreateDeviceSecure`; `FILE_DEVICE_SECURE_OPEN`; require `FILE_READ_ACCESS`/`FILE_WRITE_ACCESS` in `CTL_CODE` for state-changing IOCTLs instead of `FILE_ANY_ACCESS`.
4. **Memory**: `ExAllocatePool2` (zeroed, non-executable), `POOL_FLAG_NON_PAGED` only when needed; never `NonPagedPool` (executable); HVCI/memory-integrity compatible (no RWX, no writing to code).
5. **Never expose primitives**: no IOCTL that maps arbitrary physical memory, reads/writes arbitrary MSRs/ports, or copies to caller-supplied kernel addresses.
6. **Strings**: `RtlStringCch*`/`RtlUnicodeString*` safe functions (`ntstrsafe.h`).
7. Reference implementation: `templates/drivers/windows_kmdf_ioctl_safe.c`.
8. **Tooling**: Static Driver Verifier + CodeQL (Windows driver suppression rules — required for WHCP), **Driver Verifier** with special pool during tests, InfVerif, WDK code analysis (`/analyze`). Sign via attestation or WHQL (HLK).

## macOS DriverKit / user-space drivers
- DriverKit: request only needed entitlements; validate `ExternalMethod` arguments with `IOUserClientMethodDispatch` (explicit argument counts/sizes); check the client's entitlement in `NewUserClient`.
- User-space USB/HID tools (libusb/hidapi): treat device data as untrusted input (a malicious USB device can attack the host parser); bounds-check every report; run without admin rights where possible (udev rules / WinUSB).

## Verification
- Every IOCTL has a test: valid input, short buffer, oversized length, unknown code, unprivileged caller.
- Run the driver under KASAN/Driver Verifier while fuzzing (syzkaller / IOCTL fuzzers such as kAFL on a test VM you own).
