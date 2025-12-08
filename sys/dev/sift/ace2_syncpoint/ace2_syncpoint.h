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

#ifndef _SYS_DEV_SIFT_ACE2_SYNCPOINT_H_
#define	_SYS_DEV_SIFT_ACE2_SYNCPOINT_H_

#ifdef _KERNEL

#define	pr_sift(fmt, ...)	printf((fmt), ##__VA_ARGS__)

#define	ace2_syncpoint(label, fmt, ...)					\
	__ace2_syncpoint(label, __FILE__, __LINE__, __func__, (fmt),	\
	    __VA_ARGS__)

#define	ace2_observe(seq_id, label, fmt, ...)				\
	__ace2_observe(seq_id, label, __FILE__, __LINE__, __func__,	\
	    (fmt), __VA_ARGS__)

uint64_t	__ace2_syncpoint(const char *label, const char *caller_file,
		    int caller_line, const char *caller_func, const char *fmt,
		    ...);
void		__ace2_observe(uint64_t seq_id, const char *label,
		    const char *caller_file, int caller_line,
		    const char *caller_func, const char *fmt, ...);
#endif /* !_KERNEL */

#endif /* !_SYS_DEV_SIFT_ACE2_SYNCPOINT_H_ */
