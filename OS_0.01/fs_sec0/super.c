#include "fs.h"
#include "ondisk.h"

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/namei.h>

static const struct super_operations simplefs_super_ops;
int simple_statfs(struct dentry *dentry, struct kstatfs *buf);

static struct dentry *simplefs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, simplefs_fill_super);
}

static struct file_system_type simplefs_type = {
	.owner = THIS_MODULE,
	.name = "simplefs",
	.mount = simplefs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = 0,
};

static int __init simplefs_init(void)
{
	int err = register_filesystem(&simplefs_type);
	pr_info("simplefs: registered\n");
	return err;
}

static void __exit simplefs_exit(void)
{
	unregister_filesystem(&simplefs_type);
	pr_info("simplefs: unregistered\n");
}

module_init(simplefs_init);
module_exit(simplefs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("shahriar-dhrubo");
MODULE_DESCRIPTION("basic kernel file system");
