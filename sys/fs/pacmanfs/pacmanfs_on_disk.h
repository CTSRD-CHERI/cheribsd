#ifndef PACMANFS_ON_DISK_H
#define PACMANFS_ON_DISK_H

#include <linux/types.h>
#include <linux/magic.h>

typedef uint32_t block_number_t;
typedef uint32_t inode_number_t;

struct pacmanfs_sb_disk {
	uint32_t s_magic;
	inode_number_t root_directory;
	inode_number_t next_free_inode;

	block_number_t inode_array_start;
	uint64_t inode_array_block_count;

	block_number_t data_blocks_start;
	uint64_t data_blocks_block_count;

	block_number_t free_list_start;
	uint64_t free_list_block_count; // block length
	uint64_t free_list_length; // entry length
};

#define pacmanfs_IN(inode) ((struct pacmanfs_inode_disk *)inode->i_private)

struct pacmanfs_inode_disk {
	int data_tree_depth; /* make sure this comes first */
	uint16_t mode; /* make sure this comes next */

	uint32_t uid; /* both uid and gid should really */
	uint32_t gid; /* be using kernel types, but it
					   makes it a massive pain to use
					   in mkfs_pacmanfs */
	uint64_t link_count;
	uint64_t size; /* in bytes */
	uint64_t atime, ctime, mtime;
	block_number_t data;
	// probably more stuff...
};

struct pacmanfs_dirent_disk {
	inode_number_t inode;
	char name[256 - sizeof(inode_number_t)];
};

#endif /* PACMANFS_ON_DISK_H */
