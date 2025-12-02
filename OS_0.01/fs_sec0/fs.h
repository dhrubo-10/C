#ifndef _FS_H
#define _FS_H

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/time.h>

#define FS_MAGIC 0x53464E53 /* 'SFNS' */
#define FS_BLOCK_SIZE 1024
#define FS_NAME_LEN 255

#include "ondisk.h"

struct fs_sb_info {
	struct buffer_head *s_sbh; 
	struct mutex s_lock;       
	uint32_t s_inodes_count;
	uint32_t s_blocks_count;
	uint32_t s_first_data_block;
	uint32_t s_inode_table_blocks;
	unsigned long s_bmap_block;  
	unsigned long s_itable_block; 
};

static inline struct fs_sb_info *SIMPLEFS_SB(struct super_block *sb)
{ return sb->s_fs_info; }

struct fs_inode_info {
	struct inode vfs_inode;
	uint32_t i_blocks; 
	uint32_t i_block_ptrs[12]; 
};

static inline struct fs_inode_info *FS_I(struct inode *inode)
{ return container_of(inode, struct fs_inode_info, vfs_inode); }

/* prototypes */
int fs_fill_super(struct super_block *sb, void *data, int silent);
int fs_balloc(struct super_block *sb, uint32_t *block_out);
void fs_bfree(struct super_block *sb, uint32_t block);
struct inode *fs_iget(struct super_block *sb, unsigned long ino);
int fs_write_inode(struct inode *inode, struct writeback_control *wbc);
int _statfs(struct dentry *dentry, struct kstatfs *buf);

extern const struct file_operations fs_file_ops;
extern const struct file_operations _dir_operations;
extern const struct inode_operations _dir_inode_operations;
extern const struct inode_operations _file_inode_operations;

#endif
