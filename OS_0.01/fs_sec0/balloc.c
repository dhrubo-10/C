#include "fs.h"
#include "ondisk.h"

#include <linux/buffer_head.h>
#include <linux/fs.h>

/*
 * Scans the block bitmap for a free block, marks it as used, and
 * returns the corresponding block number
 */
int simplefs_balloc(struct super_block *sb, uint32_t *block_out)
{
	struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
	struct buffer_head *bh;
	uint8_t *bitmap;
	uint32_t blocks_per_byte = 8;
	uint32_t total_blocks = sbi->s_blocks_count - sbi->s_first_data_block;
	uint32_t max_bytes = DIV_ROUND_UP(total_blocks, blocks_per_byte);
	uint32_t i, j;

	bh = sb_bread(sb, sbi->s_bmap_block);
	if (!bh)
		return -EIO;

	bitmap = (uint8_t *)bh->b_data;

	for (i = 0; i < max_bytes && i < sb->s_blocksize; i++) {
		if (bitmap[i] != 0xFF) { /* byte not full */
			for (j = 0; j < 8; j++) {
				if (!(bitmap[i] & (1 << j))) {
					uint32_t block = sbi->s_first_data_block + (i * 8 + j);

					if (block >= sbi->s_blocks_count) {
						brelse(bh);
						return -ENOSPC;
					}

					bitmap[i] |= (1 << j);
					mark_buffer_dirty(bh);
					brelse(bh);

					*block_out = block;
					return 0;
				}
			}
		}
	}

	brelse(bh);
	return -ENOSPC;
}

/*
 * Marks a previously allocated block as free in the block bitmap.
 */
void simplefs_bfree(struct super_block *sb, uint32_t block)
{
	struct simplefs_sb_info *sbi = SIMPLEFS_SB(sb);
	struct buffer_head *bh;
	uint32_t idx, byte, bit;
	uint8_t *bitmap;

	if (block < sbi->s_first_data_block || block >= sbi->s_blocks_count)
		return; /* sanity check */

	idx = block - sbi->s_first_data_block;
	byte = idx / 8;
	bit = idx % 8;

	bh = sb_bread(sb, sbi->s_bmap_block);
	if (!bh)
		return;

	bitmap = (uint8_t *)bh->b_data;
	bitmap[byte] &= ~(1 << bit);
	mark_buffer_dirty(bh);
	brelse(bh);
}
