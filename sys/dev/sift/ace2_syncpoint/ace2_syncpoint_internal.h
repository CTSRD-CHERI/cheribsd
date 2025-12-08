/*-
 * Copyright (c) 2025 Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#ifndef _SYS_DEV_SIFT_ACE2_SYNCPOINT_INTERNAL_H_
#define	_SYS_DEV_SIFT_ACE2_SYNCPOINT_INTERNAL_H_

#ifdef _KERNEL
#include <sys/_mutex.h>
#include <sys/condvar.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#endif /* !_KERNEL */

/*
 * Various pieces of syncpoint state.  The SIFT implementation does not track
 * reads, but we do this for debugging purposes.  It does not affect the logic
 * of syncpoint behavior.
 */
#define	ACE2_SYNCPOINT_FLAG_WRITTEN	0x00000001  /* Write performed. */
#define	ACE2_SYNCPOINT_FLAG_CONTINUED	0x00000002  /* Syncpoint continued. */
#define	ACE2_SYNCPOINT_FLAG_READ	0x00000004  /* Read happened. */

#ifdef _KERNEL

/*
 * Data structure describing a specific event / complation.  Allocated each
 * time a syncpoint is hit dynamically in the kernel, and freed when (or a bit
 * after) the event is received by userlevel.
 */
struct ace2_syncpoint_completion {
	/*
	 * Entry in queue of completions.
	 */
	TAILQ_ENTRY(ace2_syncpoint_completion)	asc_entry;

	/*
	 * Structure and event synchronization.
	 */
	struct mtx	 asc_mtx;
	struct cv	 asc_cv_written;	/* Signal write occurred. */
	struct cv	 asc_cv_continued;	/* Syncpoint has continued. */

	/*
	 * Completion-specific device node.
	 */
	struct cdev	*asc_cdevsw;

	/*
	 * Event information.
	 */
	uint64_t	 asc_id;
	const char	*asc_label;
	const char	*asc_file;
	int		 asc_line;
	const char	*asc_func;

	/*
	 * Information captured for debugging purposes, used in async
	 * contexts.
	 */
	pid_t		 asc_pid;
	lwpid_t		 asc_tid;
	char		 asc_pcomm[MAXCOMLEN + 1];

	/*
	 * State of the completion.
	 */
	uint32_t	 asc_flags;
};

struct sbuf;
void	ace2_syncpoint_close(struct ace2_syncpoint_completion *ascp);
void	ace2_syncpoint_continued(struct ace2_syncpoint_completion *ascp);
void	ace2_syncpoint_destroydev(struct ace2_syncpoint_completion *ascp,
	    void (*cb)(void *));
void	ace2_syncpoint_list(struct sbuf *sb);
int	ace2_syncpoint_makedev(struct ace2_syncpoint_completion *ascp);
void	ace2_syncpoint_module_load(void);
int	ace2_syncpoint_module_unload(void);
void	ace2_syncpoint_open(struct ace2_syncpoint_completion *ascp);
void	ace2_syncpoint_read(struct ace2_syncpoint_completion *ascp);
void	ace2_syncpoint_write(struct ace2_syncpoint_completion *ascp);

/*
 * sysctls.
 */
SYSCTL_DECL(_dev_ace2);
SYSCTL_DECL(_dev_ace2_syncpoint);
SYSCTL_DECL(_dev_ace2_syncpoint_test);

extern int	ace2_syncpoint_enabled;
extern uint64_t	ace2_syncpoint_nextid;
extern uint64_t	ace2_syncpoint_count;
extern int	ace2_syncpoint_test_enabled;

#endif /* !_KERNEL */

/* XXXRW: Define vmstat sysctls here. */

#endif /* !_SYS_DEV_SIFT_ACE2_SYNCPOINT_INTERNAL_H_ */
