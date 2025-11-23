#include "fs.h"
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fsnotify.h>
#include <linux/audit.h>
#include <linux/vmalloc.h>
#include <linux/posix_acl_xattr.h>

#include <linux/uaccess.h>

ssize_t simple_xattr_list(struct inode *inode, struct simple_xattrs *xattrs,
			  char *buffer, size_t size)
{
	bool trusted = ns_capable_noaudit(&init_user_ns, CAP_SYS_ADMIN);
	struct simple_xattr *xattr;
	struct rb_node *rbp;
	ssize_t remaining_size = size;
	int err = 0;

	err = posix_acl_listxattr(inode, &buffer, &remaining_size);
	if (err)
		return err;

	err = security_inode_listsecurity(inode, buffer, remaining_size);
	if (err < 0)
		return err;

	if (buffer) {
		if (remaining_size < err)
			return -ERANGE;
		buffer += err;
	}
	remaining_size -= err;
	err = 0;

	read_lock(&xattrs->lock);
	for (rbp = rb_first(&xattrs->rb_root); rbp; rbp = rb_next(rbp)) {
		xattr = rb_entry(rbp, struct simple_xattr, rb_node);

		/* skip "trusted." attributes for unprivileged callers */
		if (!trusted && xattr_is_trusted(xattr->name))
			continue;

		/* skip MAC labels; these are provided by LSM above */
		if (xattr_is_maclabel(xattr->name))
			continue;

		err = xattr_list_one(&buffer, &remaining_size, xattr->name);
		if (err)
			break;
	}
	read_unlock(&xattrs->lock);

	return err ? err : size - remaining_size;
}


static bool rbtree_simple_xattr_less(struct rb_node *new_node,
				     const struct rb_node *node)
{
	return rbtree_simple_xattr_node_cmp(new_node, node) < 0;
}


void simple_xattr_add(struct simple_xattrs *xattrs,
		      struct simple_xattr *new_xattr)
{
	write_lock(&xattrs->lock);
	rb_add(&new_xattr->rb_node, &xattrs->rb_root, rbtree_simple_xattr_less);
	write_unlock(&xattrs->lock);
}


void simple_xattrs_init(struct simple_xattrs *xattrs)
{
	xattrs->rb_root = RB_ROOT;
	rwlock_init(&xattrs->lock);
}


void simple_xattrs_free(struct simple_xattrs *xattrs, size_t *freed_space)
{
	struct rb_node *rbp;

	if (freed_space)
		*freed_space = 0;
	rbp = rb_first(&xattrs->rb_root);
	while (rbp) {
		struct simple_xattr *xattr;
		struct rb_node *rbp_next;

		rbp_next = rb_next(rbp);
		xattr = rb_entry(rbp, struct simple_xattr, rb_node);
		rb_erase(&xattr->rb_node, &xattrs->rb_root);
		if (freed_space)
			*freed_space += simple_xattr_space(xattr->name,
							   xattr->size);
		simple_xattr_free(xattr);
		rbp = rbp_next;
	}
}
