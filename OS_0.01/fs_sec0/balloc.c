#include "fs.h"

/* Find free block in block bitmap and mark it */
int simplefs_balloc(struct super_block *sb, uint32_t *block_out)
{
	struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
	struct buffer_head *bh;
	unsigned char *bitmap;
	int i, j;

	bh = sb_bread(sb, sbi->s_bmap_block);
	if (!bh)
		return -EIO;
	bitmap = (unsigned char *)bh->b_data;

	for (i = 0; i < sb->s_blocksize; i++) {
		if (bitmap[i] != 0xFF) {
			for (j = 0; j < 8; j++) {
				if (!(bitmap[i] & (1 << j))) {
					bitmap[i] |= (1 << j);
					mark_buffer_dirty(bh);
					*block_out = sbi->s_first_data_block + (i * 8 + j);
					brelse(bh);
					return 0;
				}
			}
		}
	}
	brelse(bh);
	return -ENOSPC;
}

void simplefs_bfree(struct super_block *sb, uint32_t block)
{
	struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
	struct buffer_head *bh;
	unsigned long idx = block - sbi->s_first_data_block;
	unsigned int byte = idx / 8;
	unsigned int bit = idx % 8;

	bh = sb_bread(sb, sbi->s_bmap_block);
	if (!bh) return;
	((unsigned char *)bh->b_data)[byte] &= ~(1 << bit);
	mark_buffer_dirty(bh);
	brelse(bh);
}
