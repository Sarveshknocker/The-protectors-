// SPDX-License-Identifier: GPL-2.0
/*
 * Reference pattern: a hardened misc-device ioctl for a Linux kernel module.
 * - fixed-size ABI struct, versioned via _IOW/_IOR
 * - one copy in, validated, one copy out (no double fetch)
 * - capability check for privileged commands
 * - zeroed output structs (no kernel stack leaks)
 * - mutex around shared state
 * Adapt names; keep the patterns.
 */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#define DEMO_NAME_MAX 32

struct demo_set_req {
	__u32 id;
	__u32 len;                  /* bytes used in name[] */
	char name[DEMO_NAME_MAX];
};

struct demo_get_resp {
	__u32 id;
	__u32 len;
	char name[DEMO_NAME_MAX];
};

#define DEMO_IOC_MAGIC 'D'
#define DEMO_IOC_SET _IOW(DEMO_IOC_MAGIC, 1, struct demo_set_req)
#define DEMO_IOC_GET _IOR(DEMO_IOC_MAGIC, 2, struct demo_get_resp)

static DEFINE_MUTEX(demo_lock);
static struct demo_get_resp demo_state; /* protected by demo_lock */

static long demo_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	if (_IOC_TYPE(cmd) != DEMO_IOC_MAGIC)
		return -ENOTTY;

	switch (cmd) {
	case DEMO_IOC_SET: {
		struct demo_set_req req;

		if (!capable(CAP_SYS_ADMIN))            /* narrowest capability that fits */
			return -EPERM;
		if (copy_from_user(&req, argp, sizeof(req)))  /* single fetch */
			return -EFAULT;
		if (req.len > sizeof(req.name))         /* validate before use */
			return -EINVAL;

		mutex_lock(&demo_lock);
		memset(&demo_state, 0, sizeof(demo_state));
		demo_state.id = req.id;
		demo_state.len = req.len;
		memcpy(demo_state.name, req.name, req.len);
		mutex_unlock(&demo_lock);
		return 0;
	}
	case DEMO_IOC_GET: {
		struct demo_get_resp resp = {};         /* zeroed: padding can't leak */

		mutex_lock(&demo_lock);
		resp = demo_state;
		mutex_unlock(&demo_lock);

		if (copy_to_user(argp, &resp, sizeof(resp)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations demo_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = demo_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice demo_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "demo",
	.fops = &demo_fops,
	.mode = 0600,                               /* root only; widen via udev rule if needed */
};

module_misc_device(demo_dev);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hardened ioctl reference pattern");
