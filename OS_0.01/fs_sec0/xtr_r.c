#include "fs.h"

ssize_t simplefs_getxattr(struct dentry *dentry, const char *name, void *value, size_t size)
{
	return -ENOTSUPP;
}

int simplefs_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	return -ENOTSUPP;
}
