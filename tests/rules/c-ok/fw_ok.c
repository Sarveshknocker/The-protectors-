/* Safe twins whose rules look across several lines, kept in their own file. */
#include <linux/module.h>
#include <linux/fs.h>

void ota(void) {
    /* ok: fw.insecure-ota */
    httpUpdate.update(client, "https://fw.acme.io/firmware.bin");
}

static long demo_ioctl(struct file *f, unsigned int c, unsigned long arg) {
    struct demo_info info;
    /* ok-file: kernel.ioctl-no-capability */
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    memset(&info, 0, sizeof(info));
    /* ok: kernel.infoleak */
    if (copy_to_user((void __user *)arg, &info, sizeof(info))) return -EFAULT;
    /* ok: kernel.user-copy-unchecked */
    if (copy_from_user(&info, (void __user *)arg, sizeof(info))) return -EFAULT;
    /* ok: kernel.deprecated-api */
    strscpy(info.name, "demo", sizeof(info.name));
    return 0;
}

static const struct file_operations fops = { .unlocked_ioctl = demo_ioctl };
