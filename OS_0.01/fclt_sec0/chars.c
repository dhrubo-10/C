#include <errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/tty.h>
#include <linux/major.h>

extern int tty_read(unsigned int minor, char *buf, int count);
extern int tty_write(unsigned int minor, const char *buf, int count);
extern int lp_write(const char *buf, int count);

typedef int (*crw_ptr)(int rw, unsigned int minor, char *buf, int count);

#define NRDEVS (sizeof(crw_table) / sizeof(crw_ptr))
#define READ 0
#define WRITE 1

static int rw_ttyx(int rw, unsigned int minor, char *buf, int count);
static int rw_tty(int rw, unsigned int minor, char *buf, int count);
static int rw_null(int rw, unsigned int minor, char *buf, int count);
static int rw_lp(int rw, unsigned int minor, char *buf, int count);

static crw_ptr crw_table[] = {
	NULL,
	NULL,
	NULL,
	NULL,
	rw_ttyx,
	rw_tty,
	rw_lp,
	rw_null
};

static int rw_ttyx(int rw, unsigned int minor, char *buf, int count)
{
	if (rw == READ)
		return tty_read(minor, buf, count);
	else if (rw == WRITE)
		return tty_write(minor, buf, count);
	return -EINVAL;
}

static int rw_tty(int rw, unsigned int minor, char *buf, int count)
{
	int tty_id = current->tty;
	if (tty_id < 0)
		return -ENODEV;
	return rw_ttyx(rw, tty_id, buf, count);
}

static int rw_null(int rw, unsigned int minor, char *buf, int count)
{
	if (rw == READ)
		return 0;
	if (rw == WRITE)
		return count;
	return -EINVAL;
}

static int rw_lp(int rw, unsigned int minor, char *buf, int count)
{
	if (rw == READ)
		return -EPERM;
	if (rw == WRITE)
		return lp_write(buf, count);
	return -EINVAL;
}

int rw_char(int rw, int dev, char *buf, int count)
{
	crw_ptr call_addr;
	int major = MAJOR(dev), minor = MINOR(dev);

	if (major >= NRDEVS)
		return -ENODEV;

	call_addr = crw_table[major];
	if (!call_addr)
		return -ENODEV;

	if (count < 0)
		return -EINVAL;

	if (!access_ok(buf, count))
		return -EFAULT;

	return call_addr(rw, minor, buf, count);
}

int register_chrdev_handler(int major, crw_ptr handler)
{
	if (major < 0 || major >= NRDEVS)
		return -EINVAL;
	if (crw_table[major])
		return -EBUSY;
	crw_table[major] = handler;
	return 0;
}

int unregister_chrdev_handler(int major)
{
	if (major < 0 || major >= NRDEVS)
		return -EINVAL;
	crw_table[major] = NULL;
	return 0;
}

int rw_char_user(int rw, int dev, char __user *ubuf, int count)
{
	char *kbuf;
	int ret;

	if (count <= 0)
		return 0;
	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (rw == WRITE) {
		if (copy_from_user(kbuf, ubuf, count)) {
			kfree(kbuf);
			return -EFAULT;
		}
		ret = rw_char(WRITE, dev, kbuf, count);
	} else {
		ret = rw_char(READ, dev, kbuf, count);
		if (ret > 0 && copy_to_user(ubuf, kbuf, ret)) {
			kfree(kbuf);
			return -EFAULT;
		}
	}

	kfree(kbuf);
	return ret;
}
