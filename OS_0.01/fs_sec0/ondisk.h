#ifndef _FS_ONDISK_H
#define _FS_ONDISK_H

#include <linux/types.h>
#include <linux/byteorder/generic.h>

#define FS_SUPER_MAGIC 0x53464E53

struct simplefs_super {
	__le32 s_magic;      
	__le32 s_inodes_count;
	__le32 s_blocks_count;
	__le32 s_first_data_block;
	__le32 s_log_block_size; /* 0 -> 1024 */
	__le32 s_inode_size;     /* bytes per inode */
	__le32 s_inode_table_blocks; /* blocks used by inode table */
	__le32 s_block_bitmap_block; /* block id for block bitmap */
	__le32 s_inode_table_block;  /* block id for inode table */
	__le32 s_reserved[8];
} __attribute__((packed));

struct fs_inode {
	__le16 i_mode;
	__le16 i_uid;
	__le32 i_size;
	__le32 i_atime;
	__le32 i_ctime;
	__le32 i_mtime;
	__le32 i_blocks;
	__le32 i_block[12];
	unsigned char i_pad[64];
} __attribute__((packed));

struct fs_dir_entry {
	__le32 inode;
	char name[256];
} __attribute__((packed));

#endif 
