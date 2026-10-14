/* Rule corpus (Linux kernel module). */
#include <linux/module.h>
#include <linux/uaccess.h>

static long demo_ioctl(struct file *f, unsigned int c, unsigned long arg) {
    struct demo_info info;
    struct demo_cmd cmd;
    /* ruleid: kernel.user-copy-unchecked */
    copy_from_user(&cmd, (void __user *)arg, sizeof(cmd));
    /* ruleid: kernel.infoleak */
    if (copy_to_user((void __user *)arg, &info, sizeof(info))) return -EFAULT;
    /* ruleid: kernel.deprecated-api */
    strlcpy(info.name, cmd.name, sizeof(info.name));
    return 0;
}

static const struct file_operations fops = {
    /* ruleid: kernel.ioctl-no-capability */
    .unlocked_ioctl = demo_ioctl,
};
