#ifndef _PACMANFS_H
#define _PACMANFS_H

#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include "pacmanfs_on_disk.h"
#define PACMANFS_BLOCKSIZE 4096

struct pacmanfs_sb_info {
	struct pacmanfs_sb_disk *s_disk;
	unsigned long		s_mount_opts;

	spinlock_t		s_lock;

	unsigned long long	s_features;
	kuid_t			s_uid;
	kgid_t			s_gid;
	umode_t			s_perm;
	uuid_t			s_uuid;
	unsigned int		s_zone_sectors_shift;

	// struct pacmanfs_zone_group s_zgroup[ZONEFS_ZTYPE_MAX];

	loff_t			s_blocks;
	loff_t			s_used_blocks;

	unsigned int		s_max_wro_seq_files;
	atomic_t		s_wro_seq_files;

	unsigned int		s_max_active_seq_files;
	atomic_t		s_active_seq_files;

	bool			s_sysfs_registered;
	struct kobject		s_kobj;
	struct completion	s_kobj_unregister;
};

#define pacmanfs_SB(sb) ((struct pacmanfs_sb_info *)((sb)->s_fs_info))
#endif /* _PACMANFS_H */
