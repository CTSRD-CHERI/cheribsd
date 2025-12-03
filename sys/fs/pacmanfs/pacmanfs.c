// SPDX-License-Identifer: GPL-2.0

/*
 * Kernel module implementing a simple filesystem for the PACMAN project.
 */

#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/statfs.h>
#include <linux/string.h>
//#include <sift/ace2_syncpoint.h> // XXX

#define PACMANFS_MAGIC          0x73697269

#include "pacmanfs.h"
#include "pacmanfs_on_disk.h"

struct file_system_type *global_fst = NULL; // XXX

#define INODES_PER_BLOCK \
	(PACMANFS_BLOCKSIZE / sizeof(struct pacmanfs_inode_disk))
#define INO_BLOCK(sb, ino)                            \
	(pacmanfs_SB(sb)->s_disk->inode_array_start + \
	 (((ino) - 1) / INODES_PER_BLOCK))
#define BLOCK_IN_INO_RANGE(block, sb)                                   \
	(((block) >= pacmanfs_SB(sb)->s_disk->inode_array_start) &&     \
	 ((block) < (pacmanfs_SB(sb)->s_disk->inode_array_block_count + \
		     pacmanfs_SB(sb)->s_disk->inode_array_start)))
#define INO_POS_IN_BLOCK(ino, block) (((ino) - 1) % INODES_PER_BLOCK)
#define INODE_POS_IN_BLOCK(inode, block) INO_POS_IN_BLOCK((inode)->i_ino, block)

const struct file_operations pacmanfs_dir_operations;
const struct file_operations pacmanfs_file_operations;
const struct inode_operations pacmanfs_inode_ops;
const struct inode_operations pacmanfs_symlink_inode_ops;

static struct timespec64 make_ts64(uint64_t seconds)
{
	struct timespec64 t = {
		.tv_sec = seconds,
		.tv_nsec = 0,
	};
	return t;
}

#define BLOCK_PTRS_IN_BLOCK (PACMANFS_BLOCKSIZE / sizeof(block_number_t))

static inline block_number_t free_list_tail(struct pacmanfs_sb_disk *sb_disk)
{
	block_number_t start = sb_disk->free_list_start;
	block_number_t length = sb_disk->free_list_length;
	if (length == 0)
		return start;
	return start + ((length - 1) / BLOCK_PTRS_IN_BLOCK);
}

static block_number_t pop_free_block(struct super_block *sb)
{
	struct pacmanfs_sb_disk *sb_disk = pacmanfs_SB(sb)->s_disk;
	if (sb_disk->free_list_length <= 0) {
		pr_emerg("pacmanfs: out of free blocks");
		return 0;
	}
	block_number_t b = free_list_tail(sb_disk);
	struct buffer_head *bh;
	if (!(bh = sb_bread(sb, b))) {
		pr_err("pacmanfs: could not read free list (block %d)", b);
		return 0;
	}
	block_number_t *list_block = (block_number_t *)bh->b_data;
	int position_in_block =
		(sb_disk->free_list_length - 1) % BLOCK_PTRS_IN_BLOCK;
	block_number_t free_block = list_block[position_in_block];

	list_block[position_in_block] = 0;

	pacmanfs_SB(sb)->s_disk->free_list_length--;

	mark_buffer_dirty(bh);
	brelse(bh);

	// zero out the block
	bh = NULL;
	if (!(bh = sb_bread(sb, free_block))) {
		pr_err("pacmanfs: could not read new free block (block %d)",
		       free_block);
		return 0;
	}
	memset(bh->b_data, 0, PACMANFS_BLOCKSIZE);
	mark_buffer_dirty(bh);
	brelse(bh);
	return free_block;
}

static int push_free_block(struct super_block *sb, block_number_t block)
{
	struct pacmanfs_sb_disk *sb_disk = pacmanfs_SB(sb)->s_disk;
	if (sb_disk->free_list_length >=
	    (sb_disk->free_list_block_count * BLOCK_PTRS_IN_BLOCK)) {
		pr_emerg("pacmanfs: free block list out of space");
		return 1;
	}
	block_number_t b = free_list_tail(sb_disk);
	struct buffer_head *bh;
	if (!(bh = sb_bread(sb, b))) {
		pr_err("pacmanfs: could not read free list (block %d)", b);
		return 1;
	}

	block_number_t *list_block = (block_number_t *)bh->b_data;
	int position_in_block =
		(sb_disk->free_list_length - 1) % BLOCK_PTRS_IN_BLOCK;
	list_block[position_in_block + 1] = block;

	pacmanfs_SB(sb)->s_disk->free_list_length++;

	mark_buffer_dirty(bh);
	brelse(bh);
	return 0;
}

/**
 * Gets an inode from the disk.
 * Note that sometimes you _do_ actually just want a `struct inode` instead, not the one from
 * disk. (I.E. this ignores the inode cache).
 * The buffer head will be allocated by this function and it is on you to @brelse() it!
 * On error, returns NULL. In that case, the buffer head will not have been allocated.
 */
static struct pacmanfs_inode_disk *
pacmanfs_get_inode_disk(struct super_block *sb, struct buffer_head **bh,
			inode_number_t ino)
{
	block_number_t block = INO_BLOCK(sb, ino);
	if (!BLOCK_IN_INO_RANGE(block, sb)) {
		pr_err("pacmanfs: tried to write out of range inode");
		return NULL;
	}

	if (!(*bh = sb_bread(sb, block))) {
		pr_err("pacmanfs: could not read inode block");
		return NULL;
	}

	struct pacmanfs_inode_disk *inode_block =
		(struct pacmanfs_inode_disk *)((*bh)->b_data);
	struct pacmanfs_inode_disk *inode_disk =
		inode_block + INO_POS_IN_BLOCK(ino, block);

	return inode_disk;
}

/**
 * Fills an inode from disk.
 * If parent_dir is passed, uses that in inode_init_owner; otherwise,
 * you can pass NULL.
 */
static int fill_inode(struct pacmanfs_inode_disk *inode_disk,
		      struct inode *inode_mem, struct inode *parent_dir)
{
	struct pacmanfs_inode_disk *new_inode_disk =
		kzalloc(sizeof(struct pacmanfs_inode_disk), GFP_KERNEL);
	if (!new_inode_disk)
		return -ENOMEM; // no memory
	// TODO is nop_mnt_idmap the right thing here
	inode_init_owner(&nop_mnt_idmap, inode_mem, parent_dir,
			 inode_disk->mode);
	// set a/c/mtime to current time
	inode_set_ctime_to_ts(inode_mem, make_ts64(inode_disk->ctime));
	inode_set_atime_to_ts(inode_mem, make_ts64(inode_disk->atime));
	inode_set_mtime_to_ts(inode_mem, make_ts64(inode_disk->mtime));

	inode_mem->i_mode = inode_disk->mode;
	inode_mem->i_gid = make_kgid(&init_user_ns, inode_disk->gid);
	inode_mem->i_uid = make_kuid(&init_user_ns, inode_disk->uid);

	set_nlink(inode_mem, inode_disk->link_count);
	inode_mem->i_size = inode_disk->size;

	// Set up inode operations based on file type
	if (S_ISREG(inode_disk->mode)) { // regular files
		inode_mem->i_op = &pacmanfs_inode_ops;
		inode_mem->i_fop = &pacmanfs_file_operations;
	} else if (S_ISDIR(inode_disk->mode)) { // directories
		inode_mem->i_op = &pacmanfs_inode_ops;
		inode_mem->i_fop = &pacmanfs_dir_operations;
	} else if (S_ISLNK(inode_disk->mode)) { // symlinks
		inode_mem->i_op = &pacmanfs_symlink_inode_ops;
		inode_nohighmem(inode_mem);
	}

	memcpy(new_inode_disk, inode_disk, sizeof(struct pacmanfs_inode_disk));

	inode_mem->i_private = new_inode_disk;

	return 0;
}

/**
 * Gets an inode, either from disk or from the cache.
 * If the inode is new (i.e. needs to be gotten from disk), you can pass parent_dir
 * to help fill it in.
 */
static struct inode *pacmanfs_get_inode(struct super_block *sb,
					inode_number_t ino,
					struct inode *parent_dir)
{
	struct inode *inode = iget_locked(sb, ino);
	if (!inode->i_private) {
		struct buffer_head *bh = NULL;
		struct pacmanfs_inode_disk *inode_disk =
			pacmanfs_get_inode_disk(sb, &bh, ino);
		if (inode_disk == NULL) {
			pr_err("pacmanfs: could not get inode from disk");
			__destroy_inode(inode);
			return ERR_PTR(-EIO);
		}
		fill_inode(inode_disk, inode, parent_dir);
		brelse(bh);
	}

	if (inode->i_flags & I_NEW) {
		unlock_new_inode(inode);
	}

	return inode;
}

static block_number_t get_nth_block_inner(struct super_block *sb,
					  block_number_t current_block,
					  int data_tree_depth, int *count,
					  int n)
{
	if (unlikely(data_tree_depth <= 0)) {
		// huh?
		return 0;
	} else if (data_tree_depth == 1) {
		struct buffer_head *bh = NULL;
		if (!(bh = sb_bread(sb, current_block))) {
			pr_err("pacmanfs: error reading block");
			return 0;
		}
		block_number_t *block = (block_number_t *)bh->b_data;
		while (*block) {
			if (*count == n) {
				// found it!
				brelse(bh);
				return *block;
			}
			*count += 1;
			block++;
		}
		// not in this block :(
		brelse(bh);
		return 0;

	} else {
		struct buffer_head *bh = NULL;
		if (!(bh = sb_bread(sb, current_block))) {
			pr_err("pacmanfs: error reading block");
			return 0;
		}
		block_number_t *block = (block_number_t *)bh->b_data;
		while (*block) {
			block_number_t b = get_nth_block_inner(
				sb, *block, data_tree_depth - 1, count, n);
			if (b != 0) {
				// found it!
				brelse(bh);
				return b;
			}
			block++;
		}
		// not in this block :(
		brelse(bh);
		return 0;
	}
}

/**
 * Retrieve the nth data block from an inode's data.
 * If the block is not in range (i.e. there is no nth data block), returns 0.
 * (n is zero-indexed)
 */
static block_number_t get_nth_block(struct inode *inode, int n)
{
	struct pacmanfs_inode_disk *inode_disk = inode->i_private;
	int data_tree_depth;
	block_number_t data;
	if (inode_disk) {
		data_tree_depth = inode_disk->data_tree_depth;
		data = inode_disk->data;
	} else {
		struct buffer_head *bh = NULL;
		inode_disk =
			pacmanfs_get_inode_disk(inode->i_sb, &bh, inode->i_ino);
		if (!inode_disk) {
			pr_err("pacmanfs: could not get inode from disk");
			return 0;
		}
		data_tree_depth = inode_disk->data_tree_depth;
		data = inode_disk->data;
		brelse(bh);
	}

	if (data == 0) {
		return 0;
	}
	if (data_tree_depth == 0) {
		return n == 0 ? data : 0;
	}
	int count = 0;
	return get_nth_block_inner(inode->i_sb, data, data_tree_depth, &count,
				   n);
}
/**
 * @brief Recursively traverses the block tree to allocate data blocks.
 *
 * @param sb The super_block.
 * @param block_num The block number of the current indirect block.
 * @param depth The current depth (1 for single-indirect, 2 for double, etc.).
 * @param num_blocks_to_fill Counter for blocks we still need to find space for.
 * @return 0 on success, or a negative error code.
 */
static int allocate_blocks_recursive(struct super_block *sb,
				     block_number_t block_num, int depth,
				     size_t *num_blocks_to_fill)
{
	if (*num_blocks_to_fill == 0) {
		return 0; // All requested blocks have been allocated.
	}

	struct buffer_head *bh = sb_bread(sb, block_num);
	if (!bh) {
		pr_err("pacmanfs: could not read indirect block %u at depth %d\n",
		       block_num, depth);
		return -EIO;
	}

	block_number_t *ptr = (block_number_t *)bh->b_data;

	for (int i = 0; i < BLOCK_PTRS_IN_BLOCK; i++, ptr++) {
		if (*num_blocks_to_fill == 0) {
			break;
		}

		// If a pointer is empty, we must allocate a block for it.
		if (*ptr == 0) {
			block_number_t new_block = pop_free_block(sb);
			if (!new_block) {
				pr_err("pacmanfs: could not get free block");
				brelse(bh);
				return -EIO;
			}
			*ptr = new_block;
			mark_buffer_dirty(bh);
		}

		if (depth == 1) {
			// Base case: Pointers at this level point to data blocks.
			// We've ensured a block exists at *ptr, so we can count it.
			(*num_blocks_to_fill)--;
		} else {
			// Recursive step: Pointers lead to another indirect block.
			int ret = allocate_blocks_recursive(sb, *ptr, depth - 1,
							    num_blocks_to_fill);
			if (ret) {
				brelse(bh);
				return ret;
			}
		}
	}

	brelse(bh);
	return 0;
}

/**
 * Ensure space exists for at least `bytes` bytes in this inode.
 * This version is refactored to handle arbitrary data_tree_depth.
 */
static int allocate_space(struct inode *inode, size_t bytes)
{
	struct pacmanfs_inode_disk *inode_disk;
	struct buffer_head *bh = NULL;
	struct super_block *sb = inode->i_sb;

	inode_disk = pacmanfs_get_inode_disk(sb, &bh, inode->i_ino);
	if (inode_disk == NULL) {
		pr_err("pacmanfs: could not get inode %lu from disk\n",
		       inode->i_ino);
		return -EIO;
	}

	// Calculate the total number of blocks the file must have.
	size_t total_blocks_needed =
		(bytes + PACMANFS_BLOCKSIZE - 1) / PACMANFS_BLOCKSIZE;

	// --- 1. Grow Tree Depth If Necessary ---
	while (1) {
		// Calculate the maximum number of blocks the current tree can hold.
		size_t max_blocks = 1;
		int shift_amount = 9 * inode_disk->data_tree_depth;
		if (shift_amount >= sizeof(max_blocks) * 8) {
			brelse(bh);
			return -EFBIG;
		} else {
			max_blocks <<= shift_amount;
		}

		if (total_blocks_needed <= max_blocks) {
			break; // Current depth is sufficient.
		}

		// The tree isn't deep enough. Add a new root level.
		block_number_t new_root = pop_free_block(sb);
		if (!new_root) {
			pr_err("pacmanfs: could not get free block");
			brelse(bh);
			return -EIO;
		}
		struct buffer_head *new_root_bh = sb_bread(sb, new_root);
		if (!new_root_bh) {
			pr_err("pacmanfs: failed to read block for new tree root\n");
			brelse(bh);
			return -EIO;
		}

		// The old root becomes the first entry in the new root.
		memset(new_root_bh->b_data, 0, PACMANFS_BLOCKSIZE);
		*((block_number_t *)new_root_bh->b_data) = inode_disk->data;

		// Update the inode to point to the new root and increment depth.
		inode_disk->data = new_root;
		inode_disk->data_tree_depth++;

		mark_buffer_dirty(new_root_bh);
		brelse(new_root_bh);
		mark_buffer_dirty(bh); // Mark inode as dirty since it changed.
	}

	// --- 2. Allocate Data Blocks ---
	if (inode_disk->data == 0 && total_blocks_needed > 0) {
		// Allocate the very first block if the inode is completely empty.
		block_number_t first_block = pop_free_block(sb);
		if (!first_block) {
			pr_err("pacmanfs: could not get free block");
			brelse(bh);
			return -EIO;
		}
		inode_disk->data = first_block;
		mark_buffer_dirty(bh);
	}

	// If this is an indirect tree, recursively allocate remaining blocks.
	if (inode_disk->data_tree_depth > 0) {
		// We track the number of file blocks to fill, not total blocks needed.
		// This is a simplification; a full implementation would track blocks already allocated.
		// For this allocation function, we assume we're filling it up to `total_blocks_needed`.
		size_t blocks_to_fill = total_blocks_needed;
		int ret = allocate_blocks_recursive(sb, inode_disk->data,
						    inode_disk->data_tree_depth,
						    &blocks_to_fill);
		if (ret) {
			brelse(bh);
			return ret;
		}
	}

	if (inode->i_private) {
		// awesome variable name
		struct pacmanfs_inode_disk *inode_disk_mem = pacmanfs_IN(inode);
		*inode_disk_mem = *inode_disk;
	}

	brelse(bh);
	return 0;
}

#define DIRENTS_IN_BLOCK \
	(PACMANFS_BLOCKSIZE / sizeof(struct pacmanfs_dirent_disk))
static int pacmanfs_iterate(struct file *filp, struct dir_context *ctx)
{
	struct super_block *sb = filp->f_inode->i_sb;
	struct buffer_head *bh = NULL;
	block_number_t block;
	unsigned long block_idx;
	unsigned long offset_in_block;

	if (ctx->pos == 0) {
		if (!dir_emit_dots(filp, ctx)) {
			// Buffer was too small even for '.' and '..'
			return 0;
		}
	}

	block_idx = (ctx->pos - 2) / DIRENTS_IN_BLOCK;
	offset_in_block = (ctx->pos - 2) % DIRENTS_IN_BLOCK;

	while ((block = get_nth_block(filp->f_inode, block_idx))) {
		bh = sb_bread(sb, block);
		if (!bh) {
			pr_err("pacmanfs: could not read data block %d", block);
			return -EIO;
		}

		struct pacmanfs_dirent_disk *dirent =
			(struct pacmanfs_dirent_disk *)bh->b_data;

		dirent += offset_in_block;

		while (offset_in_block < DIRENTS_IN_BLOCK) {
			// An inode of 0 marks an unused directory entry.
			if (dirent->inode != 0) {
				if (!dir_emit(
					    ctx, dirent->name,
					    strnlen(dirent->name,
						    sizeof_field(
							    struct pacmanfs_dirent_disk,
							    name)),
					    dirent->inode, DT_UNKNOWN)) {
					brelse(bh);
					return 0;
				}
			}

			// Advance to the next logical position.
			ctx->pos++;
			dirent++;
			offset_in_block++;
		}

		brelse(bh);

		block_idx++;
		offset_in_block = 0;
	}

	return 0;
}
static struct dentry *pacmanfs_lookup(struct inode *parent_inode,
				      struct dentry *child_dentry,
				      unsigned int flags)
{
	struct super_block *sb = parent_inode->i_sb;
	struct buffer_head *bh = NULL;
	int i = 0;
	block_number_t block = 0;
	while ((block = get_nth_block(parent_inode, i))) {
		if (!(bh = sb_bread(sb, block))) {
			pr_err("pacmanfs: could not read data block");
			return ERR_PTR(-EIO);
		}
		struct pacmanfs_dirent_disk *dirent =
			(struct pacmanfs_dirent_disk *)bh->b_data;
		int j = 0;
		while (j < DIRENTS_IN_BLOCK && dirent->inode != 0) {
			if (strcmp(dirent->name, child_dentry->d_name.name) ==
			    0) {
				// found it!
				struct inode *inode = pacmanfs_get_inode(
					sb, dirent->inode, parent_inode);
				d_add(child_dentry, inode);
				brelse(bh);
				return NULL;
			}
			dirent++;
			j++;
		}
		brelse(bh);
		i++;
	}
	d_add(child_dentry, NULL);
	return NULL;
}

static int pacmanfs_open(struct inode *inode, struct file *f)
{
	return 0;
}

static ssize_t pacmanfs_read(struct file *filp, char __user *buf, size_t len,
			     loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	//ace2_syncpoint("PACMANFS_EXP1", "inode = 0x%px\n", inode->i_private);
	struct super_block *sb = inode->i_sb;
	// Check bounds
	if (*ppos >= inode->i_size)
		return 0; // EOF
	// Get inode from disk
	struct buffer_head *bh;
	struct pacmanfs_inode_disk *inode_disk =
		pacmanfs_get_inode_disk(sb, &bh, inode->i_ino);
	if (!inode_disk)
		return -EIO;
	brelse(bh);
	// Calculate how much to read
	size_t remaining = inode->i_size - *ppos;
	size_t to_read = min(len, remaining);
	block_number_t block;
	loff_t i = (*ppos) / PACMANFS_BLOCKSIZE;
	size_t have_read = 0;
	loff_t offset = (*ppos) % PACMANFS_BLOCKSIZE;
	char __user * __capability current_buf = (__cheri_tocap char * __capability)buf;
	while (to_read > 0 && (block = get_nth_block(inode, i))) {
		// Read data block
		if (!(bh = sb_bread(sb, block))) {
			return have_read;
		}
		// Copy to user buffer
		size_t now_reading = umin(to_read, PACMANFS_BLOCKSIZE - offset);
		if (copy_to_user(current_buf, bh->b_data + offset,
				 now_reading)) {
			brelse(bh);
			return have_read;
		}
		*ppos += now_reading;
		current_buf += now_reading;
		have_read += now_reading;
		to_read -= now_reading;
		offset = 0;
		brelse(bh);
		i++;
	}
	return have_read;
}

static ssize_t pacmanfs_write(struct file *filp, const char __user *buf,
			      size_t len, loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	// Get inode from disk
	struct buffer_head *bh;
	struct pacmanfs_inode_disk *inode_disk =
		pacmanfs_get_inode_disk(sb, &bh, inode->i_ino);
	if (!inode_disk) {
		pr_err("pacmanfs: could not read inode from disk");
		return -EIO;
	}
	// Calculate how much to write
	loff_t total_size_needed = (*ppos) + len;
	if (allocate_space(inode, total_size_needed)) {
		pr_err("pacmanfs: could not allocate space for write");
		return -EIO;
	}
	// Update file size if we extended it
	loff_t new_size = max((loff_t)inode_disk->size, total_size_needed);
	inode_disk->size = new_size;
	inode->i_size = new_size;
	if (inode->i_private) {
		pacmanfs_IN(inode)->size = new_size;
	}
	size_t to_write = len;
	block_number_t block;
	int i = (*ppos) / PACMANFS_BLOCKSIZE;
	size_t have_written = 0;
	loff_t offset = (*ppos) % PACMANFS_BLOCKSIZE;
	const char __user * __capability current_buf = (__cheri_tocap const char * __capability)buf;
	struct buffer_head *block_bh;
	while (to_write > 0 && (block = get_nth_block(inode, i))) {
		// Read data block
		if (!(block_bh = sb_bread(sb, block))) {
			return have_written;
		}
		// Copy from user buffer
		size_t now_writing =
			umin(to_write, PACMANFS_BLOCKSIZE - offset);
		if (copy_from_user(block_bh->b_data + offset, current_buf,
				   now_writing)) {
			// on fail, could be half-written; mark as dirty
			// so that the results are consistent with what
			// userspace sees
			mark_buffer_dirty(block_bh);
			brelse(block_bh);
			return have_written;
		}
		*ppos += now_writing;
		current_buf += now_writing;
		have_written += now_writing;
		to_write -= now_writing;
		offset = 0;
		mark_buffer_dirty(block_bh);
		brelse(block_bh);
		i++;
	}
	mark_buffer_dirty(bh);
	brelse(bh);
	return have_written;
}

const struct file_operations pacmanfs_file_operations = {
	.owner = THIS_MODULE,
	.open = pacmanfs_open,
	.read = pacmanfs_read,
	.write = pacmanfs_write,
	.llseek = default_llseek, // Use kernel's default seek
};

static int pacmanfs_write_inode(struct inode *inode,
				struct writeback_control *wc)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh = NULL;

	struct pacmanfs_inode_disk *inode_disk =
		pacmanfs_get_inode_disk(sb, &bh, inode->i_ino);

	if (!inode_disk) {
		pr_err("pacmanfs: could not read inode from disk");
		return -EIO;
	}

	inode_disk->mode = pacmanfs_IN(inode)->mode;
	inode_disk->data = pacmanfs_IN(inode)->data;
	inode_disk->data_tree_depth = pacmanfs_IN(inode)->data_tree_depth;

	inode_disk->atime = inode_get_atime_sec(inode);
	inode_disk->mtime = inode_get_mtime_sec(inode);
	inode_disk->ctime = inode_get_mtime_sec(inode);
	inode_disk->link_count = inode->i_nlink;
	inode_disk->gid = from_kgid(&init_user_ns, inode->i_gid);
	inode_disk->uid = from_kuid(&init_user_ns, inode->i_uid);
	inode_disk->size = inode->i_size;

	mark_buffer_dirty(bh);
	brelse(bh);

	return 0;
}

#define DIRENT_SIZE sizeof(struct pacmanfs_dirent_disk)

static int add_dirent(struct inode *parent_dir, struct dentry *new_dentry,
		      inode_number_t ino)
{
	struct super_block *sb = parent_dir->i_sb;
	struct buffer_head *bh;
	loff_t dirent_offset = (DIRENT_SIZE * parent_dir->i_size);
	if (allocate_space(parent_dir, (dirent_offset + DIRENT_SIZE))) {
		pr_err("pacmanfs: couldn't allocate space for dirent");
		return -EIO;
	}
	loff_t block_idx = dirent_offset / PACMANFS_BLOCKSIZE;
	block_number_t block;
	if (!(block = get_nth_block(parent_dir, block_idx))) {
		pr_err("pacmanfs: couldn't find block index %ld (even after allocating...)",
		       block_idx);
		return -EIO;
	}

	if (!(bh = sb_bread(sb, block))) {
		pr_err("pacmanfs: couldn't read block");
		return -EIO;
	}
	loff_t dirent_offset_in_block = dirent_offset % PACMANFS_BLOCKSIZE;
	struct pacmanfs_dirent_disk *dirent =
		(struct pacmanfs_dirent_disk *)(bh->b_data +
						dirent_offset_in_block);
	parent_dir->i_size++;
	mark_inode_dirty(parent_dir);
	dirent->inode = ino;
	size_t name_len =
		min_t(size_t, new_dentry->d_name.len, sizeof(dirent->name) - 1);
	memcpy(dirent->name, new_dentry->d_name.name, name_len);
	dirent->name[name_len] = '\0'; // null terminate
	mark_buffer_dirty(bh);

	brelse(bh);
	return 0;
}

static inode_number_t get_max_inode(struct super_block *sb)
{
	struct pacmanfs_sb_disk *sb_disk = pacmanfs_SB(sb)->s_disk;
	return sb_disk->inode_array_block_count * INODES_PER_BLOCK;
}

static int pacmanfs_create_inode(struct mnt_idmap *idmap,
				 struct inode *parent_dir,
				 struct dentry *out_dentry, umode_t mode,
				 bool excl)
{
	struct super_block *sb = parent_dir->i_sb;
	struct pacmanfs_sb_info *sbi = pacmanfs_SB(sb);
	struct pacmanfs_inode_disk *inode_meta =
		kzalloc(sizeof(struct pacmanfs_inode_disk), GFP_KERNEL);
	if (!inode_meta) {
		pr_err("pacmanfs: couldn't allocate inode");
		return 1;
	}
	if (sbi->s_disk->next_free_inode >= get_max_inode(sb)) {
		pr_err("pacmanfs: ran out of inodes :(");
		return -ENOSPC;
	}

	// Allocate and initialize a data block for the new file
	block_number_t data_block = pop_free_block(sb);
	if (!data_block) {
		pr_err("pacmanfs: could not get free block");
		return -EIO;
	}

	inode_number_t ino = sbi->s_disk->next_free_inode + 1;
	if (add_dirent(parent_dir, out_dentry, ino)) {
		pr_err("pacmanfs: couldn't add new dirent");
		return -EIO;
	}

	// Calculate which block and position the new inode goes in
	block_number_t inode_block = INO_BLOCK(sb, ino);
	size_t inode_pos = INO_POS_IN_BLOCK(ino, inode_block);
	// Read the inode block directly
	struct buffer_head *new_inode_bh;
	if (!(new_inode_bh = sb_bread(sb, inode_block))) {
		pr_err("pacmanfs: could not read inode block");
		return -EIO;
	}

	sbi->s_disk->next_free_inode++;

	// init new inode
	struct inode *inode = new_inode(sb);
	inode->i_ino = ino;
	inode->i_mode = mode;
	inode_init_owner(&nop_mnt_idmap, inode, parent_dir, mode);
	simple_inode_init_ts(inode);
	if (S_ISREG(mode)) { // regular files
		inode->i_op = &pacmanfs_inode_ops;
		inode->i_fop = &pacmanfs_file_operations;
	} else if (S_ISDIR(mode)) { // directories
		inode->i_op = &pacmanfs_inode_ops;
		inode->i_fop = &pacmanfs_dir_operations;
	} else if (S_ISLNK(mode)) { // symlinks
		inode->i_op = &pacmanfs_symlink_inode_ops;
		inode_nohighmem(inode);
	}
	// Get pointer to the inode array in this block
	struct pacmanfs_inode_disk *inode_array =
		(struct pacmanfs_inode_disk *)new_inode_bh->b_data;
	// Point to our specific inode slot
	struct pacmanfs_inode_disk *new_inode_disk = &inode_array[inode_pos];
	// Set up the on-disk inode
	new_inode_disk->data = data_block;
	new_inode_disk->data_tree_depth = 0;
	new_inode_disk->mode = inode->i_mode;
	new_inode_disk->uid = from_kuid(&init_user_ns, inode->i_uid);
	new_inode_disk->gid = from_kgid(&init_user_ns, inode->i_gid);
	new_inode_disk->link_count = inode->i_nlink;
	new_inode_disk->size = 0; // New file starts empty
	new_inode_disk->atime = inode_get_atime_sec(inode);
	new_inode_disk->mtime = inode_get_mtime_sec(inode);
	new_inode_disk->ctime = inode_get_ctime_sec(inode);
	memcpy(inode_meta, new_inode_disk, sizeof(struct pacmanfs_inode_disk));
	inode->i_private = inode_meta;
	// emerg to try and ensure that the kernel highly values flushing this
	pr_emerg("pacmanfs: ACE2_INFO: inode=%d block=%d\n", ino, data_block);
	mark_buffer_dirty(new_inode_bh);
	brelse(new_inode_bh);
	insert_inode_hash(inode);
	mark_inode_dirty(inode);
	d_instantiate(out_dentry, inode);
	return 0;
}

static struct pacmanfs_dirent_disk *
find_named_dirent(struct inode *parent_dir, struct dentry *child_dentry,
		  struct buffer_head **bh)
{
	struct super_block *sb = parent_dir->i_sb;
	block_number_t block = 0;
	int i = 0;

	while ((block = get_nth_block(parent_dir, i))) {
		if (!(*bh = sb_bread(sb, block))) {
			pr_err("pacmanfs: could not read dir block (%d)",
			       block);
			return ERR_PTR(-EIO);
		}

		struct pacmanfs_dirent_disk *de =
			(struct pacmanfs_dirent_disk *)(*bh)->b_data;
		struct pacmanfs_dirent_disk *end = de + DIRENTS_IN_BLOCK;

		while (de < end && de->inode != 0) {
			if (strcmp(de->name, child_dentry->d_name.name) == 0) {
				return de;
			}
			de++;
		}

		brelse(*bh);
		*bh = NULL;
		i++;
	}

	return ERR_PTR(-ENOENT);
}

static struct pacmanfs_dirent_disk *find_last_dirent(struct inode *parent_dir,
						     struct buffer_head **bh)
{
	struct super_block *sb = parent_dir->i_sb;
	block_number_t block = 0;
	int i = 0;
	struct pacmanfs_dirent_disk *last_dirent = NULL;

	*bh = NULL;

	while ((block = get_nth_block(parent_dir, i))) {
		struct buffer_head *current_bh;

		if (!(current_bh = sb_bread(sb, block))) {
			pr_err("pacmanfs: could not read dir block (%d)",
			       block);
			return NULL;
		}

		struct pacmanfs_dirent_disk *de =
			(struct pacmanfs_dirent_disk *)current_bh->b_data;
		struct pacmanfs_dirent_disk *end = de + DIRENTS_IN_BLOCK;

		while (de < end && de->inode != 0) {
			last_dirent = de;
			if (*bh && *bh != current_bh) {
				brelse(*bh);
			}
			*bh = current_bh;
			de++;
		}

		if (*bh != current_bh) {
			brelse(current_bh);
		}
		i++;
	}

	return last_dirent;
}

static int remove_dirent(struct inode *parent_dir, struct dentry *child)
{
	struct buffer_head *last_bh = NULL;
	struct buffer_head *child_bh = NULL;

	struct pacmanfs_dirent_disk *last_de =
		find_last_dirent(parent_dir, &last_bh);
	if (!last_de) {
		pr_err("pacmanfs: could not get last dirent");
		return -EIO;
	}

	struct pacmanfs_dirent_disk *child_de =
		find_named_dirent(parent_dir, child, &child_bh);
	if (IS_ERR(child_de)) {
		pr_err("pacmanfs: error getting child dirent");
		if (last_bh)
			brelse(last_bh);
		return PTR_ERR(child_de);
	}

	// if they're the same dirent, just zero it
	if (child_de == last_de) {
		memset(child_de, 0, sizeof(struct pacmanfs_dirent_disk));
		mark_buffer_dirty(child_bh);
	} else {
		*child_de = *last_de;
		memset(last_de, 0, sizeof(struct pacmanfs_dirent_disk));
		mark_buffer_dirty(child_bh);
		mark_buffer_dirty(last_bh);
	}
	parent_dir->i_size--;

	if (last_bh)
		brelse(last_bh);
	if (child_bh)
		brelse(child_bh);

	return 0;
}

// Reclaim all data blocks used by this inode.
static int reclaim_data(struct inode *inode)
{
	int i = 0;
	block_number_t block = 0;
	while ((block = get_nth_block(inode, i))) {
		if (push_free_block(inode->i_sb, block)) {
			pr_err("pacmanfs: could not push block onto free list while deleting file");
			return 1;
		};
		i++;
	}
	return 0;
}

static int pacmanfs_unlink(struct inode *parent_dir, struct dentry *child)
{
	struct super_block *sb = parent_dir->i_sb;
	struct inode *child_inode =
		pacmanfs_get_inode(sb, child->d_inode->i_ino, NULL);

	if (!child_inode) {
		pr_err("pacmanfs: could not find inode to decrease the link count of");
		return -EPERM;
	}

	if (child_inode->i_ino == pacmanfs_SB(sb)->s_disk->root_directory) {
		inode_dec_link_count(child_inode);
		pr_err("pacmanfs: tried to delete root dir");
		return -EPERM;
	}

	inode_dec_link_count(child_inode);
	if (!child_inode->i_nlink) {
		int err = remove_dirent(parent_dir, child);
		if (err) {
			return err;
		}
		if (reclaim_data(child_inode)) {
			pr_err("pacmanfs: could not reclaim inode (inode %lu)",
			       child_inode->i_ino);
			return -EIO;
		}
	}
	iput(child_inode);

	return 0;
}

// Symlink creation function
static int pacmanfs_symlink(struct mnt_idmap *idmap, struct inode *parent_dir,
			    struct dentry *dentry, const char *symname)
{
	struct super_block *sb = parent_dir->i_sb;
	size_t symname_len = strlen(symname);
	int ret;

	// Create the symlink inode
	ret = pacmanfs_create_inode(idmap, parent_dir, dentry,
				    S_IFLNK | S_IRWXUGO, false);
	if (ret)
		return ret;

	// Get the newly created inode
	struct inode *inode = d_inode(dentry);

	// Allocate space for the symlink target
	ret = allocate_space(inode, symname_len);
	if (ret) {
		pr_err("pacmanfs: could not allocate space for symlink");
		return ret;
	}

	// Write the symlink target to the first data block
	block_number_t block = get_nth_block(inode, 0);
	if (!block) {
		pr_err("pacmanfs: no data block for symlink");
		return -EIO;
	}

	struct buffer_head *bh = sb_bread(sb, block);
	if (!bh) {
		pr_err("pacmanfs: could not read symlink data block");
		return -EIO;
	}

	// Copy the symlink target
	memcpy(bh->b_data, symname, symname_len);
	mark_buffer_dirty(bh);
	brelse(bh);

	// Update inode size
	inode->i_size = symname_len;
	if (inode->i_private) {
		pacmanfs_IN(inode)->size = symname_len;
	}

	// Update on-disk inode
	struct buffer_head *inode_bh;
	struct pacmanfs_inode_disk *inode_disk =
		pacmanfs_get_inode_disk(sb, &inode_bh, inode->i_ino);
	if (inode_disk) {
		inode_disk->size = symname_len;
		mark_buffer_dirty(inode_bh);
		brelse(inode_bh);
	}

	mark_inode_dirty(inode);
	return 0;
}

// Hard link creation function
static int pacmanfs_link(struct dentry *old_dentry, struct inode *parent_dir,
			 struct dentry *new_dentry)
{
	struct inode *inode = d_inode(old_dentry);
	struct super_block *sb = parent_dir->i_sb;
	// Don't allow hard links to directories
	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	struct pacmanfs_sb_info *sbi = pacmanfs_SB(sb);
	inode_number_t ino = sbi->s_disk->next_free_inode++;
	if (ino > get_max_inode(sb)) {
		pr_err("pacmanfs: ran out of inodes :(");
		return -ENOSPC;
	}
	if (add_dirent(parent_dir, new_dentry, ino)) {
		pr_err("pacmanfs: couldn't add new dirent");
		return -EIO;
	}
	// Increment link count
	inc_nlink(inode);
	if (inode->i_private) {
		pacmanfs_IN(inode)->link_count = inode->i_nlink;
	}

	// Update on-disk inode
	struct buffer_head *inode_bh;
	struct pacmanfs_inode_disk *inode_disk =
		pacmanfs_get_inode_disk(sb, &inode_bh, inode->i_ino);
	if (inode_disk) {
		inode_disk->link_count = inode->i_nlink;
		mark_buffer_dirty(inode_bh);
		brelse(inode_bh);
	}

	ihold(inode); // Increase reference count
	d_instantiate(new_dentry, inode);
	mark_inode_dirty(inode);

	return 0;
}

/**
 * Read the target of a symbolic link
 * This function is called when the VFS needs to follow a symlink
 */
static const char *pacmanfs_get_link(struct dentry *dentry, struct inode *inode,
				     struct delayed_call *done)
{
	struct buffer_head *bh;
	char *link_target;
	block_number_t block;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	// For symlinks, the target is stored in the first data block
	block = get_nth_block(inode, 0);
	if (!block) {
		pr_err("pacmanfs: symlink has no data block");
		return ERR_PTR(-EIO);
	}

	bh = sb_bread(inode->i_sb, block);
	if (!bh) {
		pr_err("pacmanfs: could not read symlink data block");
		return ERR_PTR(-EIO);
	}

	// Allocate memory for the link target
	link_target = kmalloc(inode->i_size + 1, GFP_KERNEL);
	if (!link_target) {
		brelse(bh);
		return ERR_PTR(-ENOMEM);
	}

	// Copy the symlink target and null-terminate
	memcpy(link_target, bh->b_data, inode->i_size);
	link_target[inode->i_size] = '\0';
	brelse(bh);

	// Set up deferred cleanup - the kernel will call kfree_link when done
	set_delayed_call(done, kfree_link, link_target);
	return link_target;
}

static int pacmanfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_dir,
			  struct dentry *out_dentry, umode_t mode)
{
	if (pacmanfs_create_inode(idmap, parent_dir, out_dentry, mode | S_IFDIR,
				  false)) {
		return 1;
	}

	if (allocate_space(out_dentry->d_inode, 1)) {
		return 1;
	}

	return 0;
};

static int pacmanfs_rmdir(struct inode *parent_dir, struct dentry *dir)
{
	struct buffer_head *bh = NULL;
	block_number_t block = 0;
	int i = 0;
	while ((block = get_nth_block(dir->d_inode, i))) {
		if (!(bh = sb_bread(parent_dir->i_sb, block))) {
			pr_err("pacmanfs: could not read data block");
			return -EIO;
		}

		struct pacmanfs_dirent_disk *dirent =
			(struct pacmanfs_dirent_disk *)bh->b_data;
		int j = 0;

		while (j < DIRENTS_IN_BLOCK) {
			if (dirent->inode != 0) {
				pr_err("pacmanfs: directory not empty");
				brelse(bh);
				return -ENOTEMPTY;
			}
			dirent++;
			j++;
		}
		brelse(bh);
		i++;
	}
	// if we got here, directory is empty
	return pacmanfs_unlink(parent_dir, dir);
}

static int pacmanfs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
			   struct dentry *old_dentry, struct inode *new_dir,
			   struct dentry *new_dentry, unsigned int flags)
{
	struct inode *old_inode = d_inode(old_dentry);
	struct inode *new_inode = d_inode(new_dentry);

	int err = 0;

	if (new_inode) {
		pr_alert("pacmanfs: move w/ overwrite not implemented");
		return -EPERM;
	} else {
		err = remove_dirent(old_dir, old_dentry);
		if (err) {
			pr_err("pacmanfs: could not remove old dirent");
			return err;
		}
		err = pacmanfs_link(old_dentry, new_dir, new_dentry);
		if (err) {
			pr_err("pacmanfs: could not link");
			//brelse(old_de_bh);
			return err;
		}
	}
	mark_inode_dirty(old_inode);

	return err;
}
static int pacmanfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(&nop_mnt_idmap, dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);

		pacmanfs_IN(inode)->size = attr->ia_size;

		// nominally, we should truncate here (qua minix_truncate)
		// but it's somewhat out-of-scope to do a lot of resizing anyways
		// so if you need to reclaim data blocks, just delete the file
	}

	if (attr->ia_mode) {
		struct pacmanfs_inode_disk *inode_disk = pacmanfs_IN(inode);

		inode_disk->mode = attr->ia_mode;
		pr_info("pacmanfs: setattr: mode is %d for inode %lu",
			inode_disk->mode, inode->i_ino);
	}

	setattr_copy(&nop_mnt_idmap, inode, attr);
	mark_inode_dirty(inode);

	return 0;
}

const struct file_operations pacmanfs_dir_operations = {
	.owner = THIS_MODULE,
	.iterate_shared = pacmanfs_iterate,
};

const struct inode_operations pacmanfs_inode_ops = {
	.lookup = pacmanfs_lookup,
	.create = pacmanfs_create_inode,
	.mkdir = pacmanfs_mkdir,
	.rmdir = pacmanfs_rmdir,
	.unlink = pacmanfs_unlink,
	.symlink = pacmanfs_symlink,
	.link = pacmanfs_link,
	.rename = pacmanfs_rename,
	.setattr = pacmanfs_setattr
};

const struct inode_operations pacmanfs_symlink_inode_ops = {
	.get_link = pacmanfs_get_link,
};

static int pacmanfs_sync_fs(struct super_block *sb, int wait)
{
	struct buffer_head *bh;
	if (!(bh = sb_bread(sb, 0))) {
		pr_err("pacmanfs: sb_bread failed");
		return -EIO;
	}

	struct pacmanfs_sb_disk *sb_disk =
		(struct pacmanfs_sb_disk *)bh->b_data;

	memcpy(sb_disk, pacmanfs_SB(sb)->s_disk,
	       sizeof(struct pacmanfs_sb_disk));

	mark_buffer_dirty(bh);
	brelse(bh);
	return 0;
}

static void pacmanfs_destroy_inode(struct inode *inode)
{
	if (inode->i_private != NULL) {
		kfree(inode->i_private);
	}
}

static void pacmanfs_evict_inode(struct inode *inode)
{
	// delete the inode from the disk;
	// updates disk bitmaps (if any);
	// delete the inode from the page cache by calling truncate_inode_pages();
	// delete the inode from memory by calling clear_inode() ;
	// an example is the minix_evict_inode() function from the minix file system.

	truncate_inode_pages_final(&inode->i_data);

	if (!inode->i_nlink) {
		inode_number_t ino = inode->i_ino;

		struct super_block *sb = inode->i_sb;
		struct buffer_head *bh = NULL;

		struct pacmanfs_inode_disk *inode_disk =
			pacmanfs_get_inode_disk(sb, &bh, ino);

		if (!inode_disk) {
			pr_err("pacmanfs: could not read inode from disk");
			return;
		}

		// setting this to 0 signals this inode is deleted
		inode_disk->link_count = 0;
		mark_buffer_dirty(bh);
		brelse(bh);
	}

	invalidate_inode_buffers(inode);
	clear_inode(inode);
}

static void pacmanfs_put_super(struct super_block *sb)
{
	struct pacmanfs_sb_info *sbi = pacmanfs_SB(sb);
	kfree(sbi->s_disk);
	sbi->s_disk = NULL;
	kfree(pacmanfs_SB(sb));
	sb->s_fs_info = NULL;
}

static void pacmanfs_umount_begin(struct super_block *sb)
{
	return;
}
static int pacmanfs_statfs(struct dentry *dentry, struct kstatfs *kstat)
{
	struct super_block *sb = dentry->d_sb;
	long long total_blocks =
		bdev_nr_sectors(sb->s_bdev) / (sb->s_blocksize / 512);
	kstat->f_type = PACMANFS_MAGIC;
	// TODO don't fix me :)
	kstat->f_fsid = (__kernel_fsid_t){
		.val = { 33188, 32837 },
	};
	struct pacmanfs_sb_disk *sb_disk = pacmanfs_SB(sb)->s_disk;
	kstat->f_blocks =
		total_blocks - pacmanfs_SB(sb)->s_disk->inode_array_start;
	kstat->f_namelen = sizeof_field(struct pacmanfs_dirent_disk, name);
	kstat->f_ffree = (INODES_PER_BLOCK * sb_disk->inode_array_block_count) -
			 sb_disk->next_free_inode;
	kstat->f_files = sb_disk->next_free_inode;
	kstat->f_bfree = sb_disk->free_list_length;
	kstat->f_bavail = kstat->f_bfree;
	kstat->f_bsize = 4096;
	kstat->f_ffree = 1;

	return 0;
}

static const struct super_operations pacmanfs_super_operations = {
	.write_inode = pacmanfs_write_inode,
	.sync_fs = pacmanfs_sync_fs,
	.destroy_inode = pacmanfs_destroy_inode,
	.put_super = pacmanfs_put_super,
	.umount_begin = pacmanfs_umount_begin,
	.evict_inode = pacmanfs_evict_inode,
	.statfs = pacmanfs_statfs
};

static int pacmanfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct pacmanfs_sb_info *sbi;

	sbi = kzalloc(sizeof(struct pacmanfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	spin_lock_init(&(sbi->s_lock));
	sb->s_fs_info = sbi; // our custom info

	struct buffer_head *bh;
	if (!(bh = sb_bread(sb, 0))) {
		pr_err("pacmanfs: could not read first block");
		return -EIO;
	}

	struct pacmanfs_sb_disk *sb_disk =
		kzalloc(sizeof(struct pacmanfs_sb_disk), GFP_KERNEL);
	if (!sb_disk)
		return -ENOMEM;
	memcpy(sb_disk, (struct pacmanfs_sb_disk *)bh->b_data,
	       sizeof(struct pacmanfs_sb_disk));

	sbi->s_disk = sb_disk;
	if (sb_disk->s_magic != PACMANFS_MAGIC) {
		pr_err("pacmanfs: bad magic %#x (trapped in a labyrinth!)", sb_disk->s_magic);
		brelse(bh);
		return -EINVAL;
	}

	sb->s_magic = PACMANFS_MAGIC;
	sb->s_maxbytes = sb_disk->data_blocks_block_count * PACMANFS_BLOCKSIZE;
	sb->s_op = &pacmanfs_super_operations;
	sb->s_time_gran = 1; // c/m/atime is granular to 1ns
	sb_set_blocksize(sb, PACMANFS_BLOCKSIZE);

	brelse(bh);
	bh = NULL;
	if (!(bh = sb_bread(sb, sb_disk->inode_array_start))) {
		pr_err("pacmanfs: could not read inode array");
		return -EINVAL;
	}

	// set up root inode
	struct pacmanfs_inode_disk *root_inode_disk =
		kzalloc(sizeof(struct pacmanfs_inode_disk), GFP_KERNEL);
	if (!root_inode_disk) {
		brelse(bh);
		return -ENOMEM;
	}

	memcpy(root_inode_disk, (struct pacmanfs_inode_disk *)bh->b_data,
	       sizeof(struct pacmanfs_inode_disk));

	struct inode *root_inode = new_inode(sb);
	if (!root_inode) {
		brelse(bh);
		return -ENOMEM;
	}
	insert_inode_hash(root_inode);
	inode_init_owner(&nop_mnt_idmap, root_inode, NULL,
			 root_inode_disk->mode);
	root_inode->i_ino = sb_disk->root_directory;
	fill_inode(root_inode_disk, root_inode, NULL);

	root_inode->i_op = &pacmanfs_inode_ops;
	root_inode->i_fop = &pacmanfs_dir_operations;
	root_inode->i_private = root_inode_disk;

	// make a `struct dentry` from our inode
	// and store it in our superblock
	sb->s_root = d_make_root(root_inode);

	long long total_blocks =
		bdev_nr_sectors(sb->s_bdev) / (sb->s_blocksize / 512);
	pr_info("pacmanfs: Device has %lld total blocks\n", total_blocks);

	brelse(bh);

	if (!sb->s_root)
		return -ENOMEM;

	return 0;
}

static struct dentry *pacmanfs_mount(struct file_system_type *fs_type,
				     int flags, const char *dev_name,
				     void *data)
{
	struct dentry *ret =
		mount_bdev(fs_type, flags, dev_name, data, pacmanfs_fill_super);
	if (IS_ERR(ret)) {
		pr_alert("pacmanfs: error while mounting pacmanfs\n");
	} else
		pr_info("pacmanfs: mounted on [%s]\n", dev_name);

	return ret;
}

static struct file_system_type pacmanfs_type = {
	.owner = THIS_MODULE,
	.name = "pacmanfs",
	.mount = pacmanfs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};

static int __init pacmanfs_init(void)
{
	pr_info("Hello world 1.\n");

	int ret;
	ret = register_filesystem(&pacmanfs_type);
	if (ret)
		return 1;
	/* A non 0 return means init_module failed; module can't be loaded. */
	return 0;
}

static void __exit pacmanfs_exit(void)

{
	unregister_filesystem(&pacmanfs_type);
	pr_info("Goodbye world 1.\n");
}


MODULE_VERSION(pacmanfs, 1);
MODULE_DEPEND(pacmanfs, linuxkpi, 1, 1, 1);

MODULE_DESCRIPTION("File system for the PACMAN project");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joan Zheng <jzheng@sift.net>");
MODULE_AUTHOR("Autumn Kenyon <akenyon@sift.net>");
MODULE_ALIAS_FS("pacmanfs");
module_init(pacmanfs_init);
module_exit(pacmanfs_exit);
