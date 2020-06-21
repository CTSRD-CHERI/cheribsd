/*
 * System call argument to DTrace register array converstion.
 *
 * DO NOT EDIT-- this file is automatically @generated.
 * $FreeBSD$
 * This file is part of the DTrace syscall provider.
 */

static void
systrace_args(int sysnum, void *params, uint64_t *uarg, int *n_args)
{
	int64_t *iarg  = (int64_t *) uarg;
	switch (sysnum) {
	/* nosys */
	case 0: {
		*n_args = 0;
		break;
	}
	/* sys_exit */
	case 1: {
		struct sys_exit_args *p = params;
		iarg[0] = p->rval; /* int */
		*n_args = 1;
		break;
	}
	/* fork */
	case 2: {
		*n_args = 0;
		break;
	}
	/* freebsd64_read */
	case 3: {
		struct freebsd64_read_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->buf; /* void * */
		uarg[2] = p->nbyte; /* size_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_write */
	case 4: {
		struct freebsd64_write_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->buf; /* const void * */
		uarg[2] = p->nbyte; /* size_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_open */
	case 5: {
		struct freebsd64_open_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->flags; /* int */
		iarg[2] = p->mode; /* mode_t */
		*n_args = 3;
		break;
	}
	/* close */
	case 6: {
		struct close_args *p = params;
		iarg[0] = p->fd; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_wait4 */
	case 7: {
		struct freebsd64_wait4_args *p = params;
		iarg[0] = p->pid; /* int */
		uarg[1] = (intptr_t) p->status; /* int * */
		iarg[2] = p->options; /* int */
		uarg[3] = (intptr_t) p->rusage; /* struct rusage * */
		*n_args = 4;
		break;
	}
	/* freebsd64_link */
	case 9: {
		struct freebsd64_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		uarg[1] = (intptr_t) p->to; /* const char * */
		*n_args = 2;
		break;
	}
	/* freebsd64_unlink */
	case 10: {
		struct freebsd64_unlink_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_chdir */
	case 12: {
		struct freebsd64_chdir_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* fchdir */
	case 13: {
		struct fchdir_args *p = params;
		iarg[0] = p->fd; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_chmod */
	case 15: {
		struct freebsd64_chmod_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_chown */
	case 16: {
		struct freebsd64_chown_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->uid; /* int */
		iarg[2] = p->gid; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_break */
	case 17: {
		struct freebsd64_break_args *p = params;
		uarg[0] = (intptr_t) p->nsize; /* char * */
		*n_args = 1;
		break;
	}
	/* getpid */
	case 20: {
		*n_args = 0;
		break;
	}
	/* freebsd64_mount */
	case 21: {
		struct freebsd64_mount_args *p = params;
		uarg[0] = (intptr_t) p->type; /* const char * */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->flags; /* int */
		uarg[3] = (intptr_t) p->data; /* void * */
		*n_args = 4;
		break;
	}
	/* freebsd64_unmount */
	case 22: {
		struct freebsd64_unmount_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->flags; /* int */
		*n_args = 2;
		break;
	}
	/* setuid */
	case 23: {
		struct setuid_args *p = params;
		uarg[0] = p->uid; /* uid_t */
		*n_args = 1;
		break;
	}
	/* getuid */
	case 24: {
		*n_args = 0;
		break;
	}
	/* geteuid */
	case 25: {
		*n_args = 0;
		break;
	}
	/* freebsd64_ptrace */
	case 26: {
		struct freebsd64_ptrace_args *p = params;
		iarg[0] = p->req; /* int */
		iarg[1] = p->pid; /* pid_t */
		uarg[2] = (intptr_t) p->addr; /* char * */
		iarg[3] = p->data; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_recvmsg */
	case 27: {
		struct freebsd64_recvmsg_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (intptr_t) p->msg; /* struct msghdr64 * */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_sendmsg */
	case 28: {
		struct freebsd64_sendmsg_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (intptr_t) p->msg; /* const struct msghdr64 * */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_recvfrom */
	case 29: {
		struct freebsd64_recvfrom_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (intptr_t) p->buf; /* void * */
		uarg[2] = p->len; /* size_t */
		iarg[3] = p->flags; /* int */
		uarg[4] = (intptr_t) p->from; /* struct sockaddr * */
		uarg[5] = (intptr_t) p->fromlenaddr; /* __socklen_t * */
		*n_args = 6;
		break;
	}
	/* freebsd64_accept */
	case 30: {
		struct freebsd64_accept_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (intptr_t) p->name; /* struct sockaddr * */
		uarg[2] = (intptr_t) p->anamelen; /* __socklen_t * */
		*n_args = 3;
		break;
	}
	/* freebsd64_getpeername */
	case 31: {
		struct freebsd64_getpeername_args *p = params;
		iarg[0] = p->fdes; /* int */
		uarg[1] = (intptr_t) p->asa; /* struct sockaddr * */
		uarg[2] = (intptr_t) p->alen; /* __socklen_t * */
		*n_args = 3;
		break;
	}
	/* freebsd64_getsockname */
	case 32: {
		struct freebsd64_getsockname_args *p = params;
		iarg[0] = p->fdes; /* int */
		uarg[1] = (intptr_t) p->asa; /* struct sockaddr * */
		uarg[2] = (intptr_t) p->alen; /* __socklen_t * */
		*n_args = 3;
		break;
	}
	/* freebsd64_access */
	case 33: {
		struct freebsd64_access_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->amode; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_chflags */
	case 34: {
		struct freebsd64_chflags_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		uarg[1] = p->flags; /* u_long */
		*n_args = 2;
		break;
	}
	/* fchflags */
	case 35: {
		struct fchflags_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = p->flags; /* u_long */
		*n_args = 2;
		break;
	}
	/* sync */
	case 36: {
		*n_args = 0;
		break;
	}
	/* kill */
	case 37: {
		struct kill_args *p = params;
		iarg[0] = p->pid; /* int */
		iarg[1] = p->signum; /* int */
		*n_args = 2;
		break;
	}
	/* getppid */
	case 39: {
		*n_args = 0;
		break;
	}
	/* dup */
	case 41: {
		struct dup_args *p = params;
		uarg[0] = p->fd; /* u_int */
		*n_args = 1;
		break;
	}
	/* getegid */
	case 43: {
		*n_args = 0;
		break;
	}
	/* freebsd64_profil */
	case 44: {
		struct freebsd64_profil_args *p = params;
		uarg[0] = (intptr_t) p->samples; /* char * */
		uarg[1] = p->size; /* size_t */
		uarg[2] = p->offset; /* size_t */
		uarg[3] = p->scale; /* u_int */
		*n_args = 4;
		break;
	}
	/* freebsd64_ktrace */
	case 45: {
		struct freebsd64_ktrace_args *p = params;
		uarg[0] = (intptr_t) p->fname; /* const char * */
		iarg[1] = p->ops; /* int */
		iarg[2] = p->facs; /* int */
		iarg[3] = p->pid; /* int */
		*n_args = 4;
		break;
	}
	/* getgid */
	case 47: {
		*n_args = 0;
		break;
	}
	/* freebsd64_getlogin */
	case 49: {
		struct freebsd64_getlogin_args *p = params;
		uarg[0] = (intptr_t) p->namebuf; /* char * */
		uarg[1] = p->namelen; /* u_int */
		*n_args = 2;
		break;
	}
	/* freebsd64_setlogin */
	case 50: {
		struct freebsd64_setlogin_args *p = params;
		uarg[0] = (intptr_t) p->namebuf; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_acct */
	case 51: {
		struct freebsd64_acct_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_sigaltstack */
	case 53: {
		struct freebsd64_sigaltstack_args *p = params;
		uarg[0] = (intptr_t) p->ss; /* const struct sigaltstack64 * */
		uarg[1] = (intptr_t) p->oss; /* struct sigaltstack64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64_ioctl */
	case 54: {
		struct freebsd64_ioctl_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = p->com; /* u_long */
		uarg[2] = (intptr_t) p->data; /* char * */
		*n_args = 3;
		break;
	}
	/* reboot */
	case 55: {
		struct reboot_args *p = params;
		iarg[0] = p->opt; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_revoke */
	case 56: {
		struct freebsd64_revoke_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_symlink */
	case 57: {
		struct freebsd64_symlink_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		uarg[1] = (intptr_t) p->link; /* const char * */
		*n_args = 2;
		break;
	}
	/* freebsd64_readlink */
	case 58: {
		struct freebsd64_readlink_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		uarg[1] = (intptr_t) p->buf; /* char * */
		uarg[2] = p->count; /* size_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_execve */
	case 59: {
		struct freebsd64_execve_args *p = params;
		uarg[0] = (intptr_t) p->fname; /* const char * */
		uarg[1] = (intptr_t) p->argv; /* char ** */
		uarg[2] = (intptr_t) p->envv; /* char ** */
		*n_args = 3;
		break;
	}
	/* umask */
	case 60: {
		struct umask_args *p = params;
		iarg[0] = p->newmask; /* mode_t */
		*n_args = 1;
		break;
	}
	/* freebsd64_chroot */
	case 61: {
		struct freebsd64_chroot_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_msync */
	case 65: {
		struct freebsd64_msync_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* void * */
		uarg[1] = p->len; /* size_t */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* vfork */
	case 66: {
		*n_args = 0;
		break;
	}
	/* sbrk */
	case 69: {
		struct sbrk_args *p = params;
		iarg[0] = p->incr; /* int */
		*n_args = 1;
		break;
	}
	/* sstk */
	case 70: {
		struct sstk_args *p = params;
		iarg[0] = p->incr; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_munmap */
	case 73: {
		struct freebsd64_munmap_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* void * */
		uarg[1] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_mprotect */
	case 74: {
		struct freebsd64_mprotect_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* const void * */
		uarg[1] = p->len; /* size_t */
		iarg[2] = p->prot; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_madvise */
	case 75: {
		struct freebsd64_madvise_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* void * */
		uarg[1] = p->len; /* size_t */
		iarg[2] = p->behav; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_mincore */
	case 78: {
		struct freebsd64_mincore_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* const void * */
		uarg[1] = p->len; /* size_t */
		uarg[2] = (intptr_t) p->vec; /* char * */
		*n_args = 3;
		break;
	}
	/* freebsd64_getgroups */
	case 79: {
		struct freebsd64_getgroups_args *p = params;
		uarg[0] = p->gidsetsize; /* u_int */
		uarg[1] = (intptr_t) p->gidset; /* gid_t * */
		*n_args = 2;
		break;
	}
	/* freebsd64_setgroups */
	case 80: {
		struct freebsd64_setgroups_args *p = params;
		uarg[0] = p->gidsetsize; /* u_int */
		uarg[1] = (intptr_t) p->gidset; /* const gid_t * */
		*n_args = 2;
		break;
	}
	/* getpgrp */
	case 81: {
		*n_args = 0;
		break;
	}
	/* setpgid */
	case 82: {
		struct setpgid_args *p = params;
		iarg[0] = p->pid; /* int */
		iarg[1] = p->pgid; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_setitimer */
	case 83: {
		struct freebsd64_setitimer_args *p = params;
		iarg[0] = p->which; /* int */
		uarg[1] = (intptr_t) p->itv; /* const struct itimerval * */
		uarg[2] = (intptr_t) p->oitv; /* struct itimerval * */
		*n_args = 3;
		break;
	}
	/* freebsd64_swapon */
	case 85: {
		struct freebsd64_swapon_args *p = params;
		uarg[0] = (intptr_t) p->name; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_getitimer */
	case 86: {
		struct freebsd64_getitimer_args *p = params;
		iarg[0] = p->which; /* int */
		uarg[1] = (intptr_t) p->itv; /* struct itimerval * */
		*n_args = 2;
		break;
	}
	/* getdtablesize */
	case 89: {
		*n_args = 0;
		break;
	}
	/* dup2 */
	case 90: {
		struct dup2_args *p = params;
		uarg[0] = p->from; /* u_int */
		uarg[1] = p->to; /* u_int */
		*n_args = 2;
		break;
	}
	/* freebsd64_fcntl */
	case 92: {
		struct freebsd64_fcntl_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (intptr_t) p->arg; /* intptr_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_select */
	case 93: {
		struct freebsd64_select_args *p = params;
		iarg[0] = p->nd; /* int */
		uarg[1] = (intptr_t) p->in; /* fd_set * */
		uarg[2] = (intptr_t) p->ou; /* fd_set * */
		uarg[3] = (intptr_t) p->ex; /* fd_set * */
		uarg[4] = (intptr_t) p->tv; /* struct timeval * */
		*n_args = 5;
		break;
	}
	/* fsync */
	case 95: {
		struct fsync_args *p = params;
		iarg[0] = p->fd; /* int */
		*n_args = 1;
		break;
	}
	/* setpriority */
	case 96: {
		struct setpriority_args *p = params;
		iarg[0] = p->which; /* int */
		iarg[1] = p->who; /* int */
		iarg[2] = p->prio; /* int */
		*n_args = 3;
		break;
	}
	/* socket */
	case 97: {
		struct socket_args *p = params;
		iarg[0] = p->domain; /* int */
		iarg[1] = p->type; /* int */
		iarg[2] = p->protocol; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_connect */
	case 98: {
		struct freebsd64_connect_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (intptr_t) p->name; /* const struct sockaddr * */
		iarg[2] = p->namelen; /* __socklen_t */
		*n_args = 3;
		break;
	}
	/* getpriority */
	case 100: {
		struct getpriority_args *p = params;
		iarg[0] = p->which; /* int */
		iarg[1] = p->who; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_bind */
	case 104: {
		struct freebsd64_bind_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (intptr_t) p->name; /* const struct sockaddr * */
		iarg[2] = p->namelen; /* __socklen_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_setsockopt */
	case 105: {
		struct freebsd64_setsockopt_args *p = params;
		iarg[0] = p->s; /* int */
		iarg[1] = p->level; /* int */
		iarg[2] = p->name; /* int */
		uarg[3] = (intptr_t) p->val; /* const void * */
		iarg[4] = p->valsize; /* __socklen_t */
		*n_args = 5;
		break;
	}
	/* listen */
	case 106: {
		struct listen_args *p = params;
		iarg[0] = p->s; /* int */
		iarg[1] = p->backlog; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_gettimeofday */
	case 116: {
		struct freebsd64_gettimeofday_args *p = params;
		uarg[0] = (intptr_t) p->tp; /* struct timeval * */
		uarg[1] = (intptr_t) p->tzp; /* struct timezone * */
		*n_args = 2;
		break;
	}
	/* freebsd64_getrusage */
	case 117: {
		struct freebsd64_getrusage_args *p = params;
		iarg[0] = p->who; /* int */
		uarg[1] = (intptr_t) p->rusage; /* struct rusage * */
		*n_args = 2;
		break;
	}
	/* freebsd64_getsockopt */
	case 118: {
		struct freebsd64_getsockopt_args *p = params;
		iarg[0] = p->s; /* int */
		iarg[1] = p->level; /* int */
		iarg[2] = p->name; /* int */
		uarg[3] = (intptr_t) p->val; /* void * */
		uarg[4] = (intptr_t) p->avalsize; /* __socklen_t * */
		*n_args = 5;
		break;
	}
	/* freebsd64_readv */
	case 120: {
		struct freebsd64_readv_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->iovp; /* struct iovec64 * */
		uarg[2] = p->iovcnt; /* u_int */
		*n_args = 3;
		break;
	}
	/* freebsd64_writev */
	case 121: {
		struct freebsd64_writev_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->iovp; /* struct iovec64 * */
		uarg[2] = p->iovcnt; /* u_int */
		*n_args = 3;
		break;
	}
	/* freebsd64_settimeofday */
	case 122: {
		struct freebsd64_settimeofday_args *p = params;
		uarg[0] = (intptr_t) p->tv; /* const struct timeval * */
		uarg[1] = (intptr_t) p->tzp; /* const struct timezone * */
		*n_args = 2;
		break;
	}
	/* fchown */
	case 123: {
		struct fchown_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->uid; /* int */
		iarg[2] = p->gid; /* int */
		*n_args = 3;
		break;
	}
	/* fchmod */
	case 124: {
		struct fchmod_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* setreuid */
	case 126: {
		struct setreuid_args *p = params;
		iarg[0] = p->ruid; /* int */
		iarg[1] = p->euid; /* int */
		*n_args = 2;
		break;
	}
	/* setregid */
	case 127: {
		struct setregid_args *p = params;
		iarg[0] = p->rgid; /* int */
		iarg[1] = p->egid; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_rename */
	case 128: {
		struct freebsd64_rename_args *p = params;
		uarg[0] = (intptr_t) p->from; /* const char * */
		uarg[1] = (intptr_t) p->to; /* const char * */
		*n_args = 2;
		break;
	}
	/* flock */
	case 131: {
		struct flock_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->how; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_mkfifo */
	case 132: {
		struct freebsd64_mkfifo_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_sendto */
	case 133: {
		struct freebsd64_sendto_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (intptr_t) p->buf; /* const void * */
		uarg[2] = p->len; /* size_t */
		iarg[3] = p->flags; /* int */
		uarg[4] = (intptr_t) p->to; /* const struct sockaddr * */
		iarg[5] = p->tolen; /* __socklen_t */
		*n_args = 6;
		break;
	}
	/* shutdown */
	case 134: {
		struct shutdown_args *p = params;
		iarg[0] = p->s; /* int */
		iarg[1] = p->how; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_socketpair */
	case 135: {
		struct freebsd64_socketpair_args *p = params;
		iarg[0] = p->domain; /* int */
		iarg[1] = p->type; /* int */
		iarg[2] = p->protocol; /* int */
		uarg[3] = (intptr_t) p->rsv; /* int * */
		*n_args = 4;
		break;
	}
	/* freebsd64_mkdir */
	case 136: {
		struct freebsd64_mkdir_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_rmdir */
	case 137: {
		struct freebsd64_rmdir_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_utimes */
	case 138: {
		struct freebsd64_utimes_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		uarg[1] = (intptr_t) p->tptr; /* const struct timeval * */
		*n_args = 2;
		break;
	}
	/* freebsd64_adjtime */
	case 140: {
		struct freebsd64_adjtime_args *p = params;
		uarg[0] = (intptr_t) p->delta; /* const struct timeval * */
		uarg[1] = (intptr_t) p->olddelta; /* struct timeval * */
		*n_args = 2;
		break;
	}
	/* setsid */
	case 147: {
		*n_args = 0;
		break;
	}
	/* freebsd64_quotactl */
	case 148: {
		struct freebsd64_quotactl_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->cmd; /* int */
		iarg[2] = p->uid; /* int */
		uarg[3] = (intptr_t) p->arg; /* void * */
		*n_args = 4;
		break;
	}
	/* freebsd64_nlm_syscall */
	case 154: {
		struct freebsd64_nlm_syscall_args *p = params;
		iarg[0] = p->debug_level; /* int */
		iarg[1] = p->grace_period; /* int */
		iarg[2] = p->addr_count; /* int */
		uarg[3] = (intptr_t) p->addrs; /* char ** */
		*n_args = 4;
		break;
	}
	/* freebsd64_nfssvc */
	case 155: {
		struct freebsd64_nfssvc_args *p = params;
		iarg[0] = p->flag; /* int */
		uarg[1] = (intptr_t) p->argp; /* void * */
		*n_args = 2;
		break;
	}
	/* freebsd64_lgetfh */
	case 160: {
		struct freebsd64_lgetfh_args *p = params;
		uarg[0] = (intptr_t) p->fname; /* const char * */
		uarg[1] = (intptr_t) p->fhp; /* struct fhandle * */
		*n_args = 2;
		break;
	}
	/* freebsd64_getfh */
	case 161: {
		struct freebsd64_getfh_args *p = params;
		uarg[0] = (intptr_t) p->fname; /* const char * */
		uarg[1] = (intptr_t) p->fhp; /* struct fhandle * */
		*n_args = 2;
		break;
	}
	/* freebsd64_sysarch */
	case 165: {
		struct freebsd64_sysarch_args *p = params;
		iarg[0] = p->op; /* int */
		uarg[1] = (intptr_t) p->parms; /* char * */
		*n_args = 2;
		break;
	}
	/* freebsd64_rtprio */
	case 166: {
		struct freebsd64_rtprio_args *p = params;
		iarg[0] = p->function; /* int */
		iarg[1] = p->pid; /* pid_t */
		uarg[2] = (intptr_t) p->rtp; /* struct rtprio * */
		*n_args = 3;
		break;
	}
	/* freebsd64_semsys */
	case 169: {
		struct freebsd64_semsys_args *p = params;
		iarg[0] = p->which; /* int */
		uarg[1] = (intptr_t) p->a2; /* intptr_t */
		uarg[2] = (intptr_t) p->a3; /* intptr_t */
		uarg[3] = (intptr_t) p->a4; /* intptr_t */
		uarg[4] = (intptr_t) p->a5; /* intptr_t */
		*n_args = 5;
		break;
	}
	/* freebsd64_msgsys */
	case 170: {
		struct freebsd64_msgsys_args *p = params;
		iarg[0] = p->which; /* int */
		uarg[1] = (intptr_t) p->a2; /* intptr_t */
		uarg[2] = (intptr_t) p->a3; /* intptr_t */
		uarg[3] = (intptr_t) p->a4; /* intptr_t */
		uarg[4] = (intptr_t) p->a5; /* intptr_t */
		uarg[5] = (intptr_t) p->a6; /* intptr_t */
		*n_args = 6;
		break;
	}
	/* freebsd64_shmsys */
	case 171: {
		struct freebsd64_shmsys_args *p = params;
		iarg[0] = p->which; /* int */
		uarg[1] = (intptr_t) p->a2; /* intptr_t */
		uarg[2] = (intptr_t) p->a3; /* intptr_t */
		uarg[3] = (intptr_t) p->a4; /* intptr_t */
		*n_args = 4;
		break;
	}
	/* setfib */
	case 175: {
		struct setfib_args *p = params;
		iarg[0] = p->fibnum; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_ntp_adjtime */
	case 176: {
		struct freebsd64_ntp_adjtime_args *p = params;
		uarg[0] = (intptr_t) p->tp; /* struct timex * */
		*n_args = 1;
		break;
	}
	/* setgid */
	case 181: {
		struct setgid_args *p = params;
		iarg[0] = p->gid; /* gid_t */
		*n_args = 1;
		break;
	}
	/* setegid */
	case 182: {
		struct setegid_args *p = params;
		iarg[0] = p->egid; /* gid_t */
		*n_args = 1;
		break;
	}
	/* seteuid */
	case 183: {
		struct seteuid_args *p = params;
		uarg[0] = p->euid; /* uid_t */
		*n_args = 1;
		break;
	}
	/* freebsd64_pathconf */
	case 191: {
		struct freebsd64_pathconf_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->name; /* int */
		*n_args = 2;
		break;
	}
	/* fpathconf */
	case 192: {
		struct fpathconf_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->name; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_getrlimit */
	case 194: {
		struct freebsd64___getrlimit_args *p = params;
		uarg[0] = p->which; /* u_int */
		uarg[1] = (intptr_t) p->rlp; /* struct rlimit * */
		*n_args = 2;
		break;
	}
	/* freebsd64_setrlimit */
	case 195: {
		struct freebsd64___setrlimit_args *p = params;
		uarg[0] = p->which; /* u_int */
		uarg[1] = (intptr_t) p->rlp; /* struct rlimit * */
		*n_args = 2;
		break;
	}
	/* nosys */
	case 198: {
		*n_args = 0;
		break;
	}
	/* freebsd64___sysctl */
	case 202: {
		struct freebsd64___sysctl_args *p = params;
		uarg[0] = (intptr_t) p->name; /* int * */
		uarg[1] = p->namelen; /* u_int */
		uarg[2] = (intptr_t) p->old; /* void * */
		uarg[3] = (intptr_t) p->oldlenp; /* size_t * */
		uarg[4] = (intptr_t) p->new; /* const void * */
		uarg[5] = p->newlen; /* size_t */
		*n_args = 6;
		break;
	}
	/* freebsd64_mlock */
	case 203: {
		struct freebsd64_mlock_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* const void * */
		uarg[1] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_munlock */
	case 204: {
		struct freebsd64_munlock_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* const void * */
		uarg[1] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_undelete */
	case 205: {
		struct freebsd64_undelete_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_futimes */
	case 206: {
		struct freebsd64_futimes_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->tptr; /* const struct timeval * */
		*n_args = 2;
		break;
	}
	/* getpgid */
	case 207: {
		struct getpgid_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		*n_args = 1;
		break;
	}
	/* freebsd64_poll */
	case 209: {
		struct freebsd64_poll_args *p = params;
		uarg[0] = (intptr_t) p->fds; /* struct pollfd * */
		uarg[1] = p->nfds; /* u_int */
		iarg[2] = p->timeout; /* int */
		*n_args = 3;
		break;
	}
	/* lkmnosys */
	case 210: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 211: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 212: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 213: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 214: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 215: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 216: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 217: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 218: {
		*n_args = 0;
		break;
	}
	/* lkmnosys */
	case 219: {
		*n_args = 0;
		break;
	}
	/* semget */
	case 221: {
		struct semget_args *p = params;
		iarg[0] = p->key; /* key_t */
		iarg[1] = p->nsems; /* int */
		iarg[2] = p->semflg; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_semop */
	case 222: {
		struct freebsd64_semop_args *p = params;
		iarg[0] = p->semid; /* int */
		uarg[1] = (intptr_t) p->sops; /* struct sembuf * */
		uarg[2] = p->nsops; /* size_t */
		*n_args = 3;
		break;
	}
	/* msgget */
	case 225: {
		struct msgget_args *p = params;
		iarg[0] = p->key; /* key_t */
		iarg[1] = p->msgflg; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_msgsnd */
	case 226: {
		struct freebsd64_msgsnd_args *p = params;
		iarg[0] = p->msqid; /* int */
		uarg[1] = (intptr_t) p->msgp; /* const void * */
		uarg[2] = p->msgsz; /* size_t */
		iarg[3] = p->msgflg; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_msgrcv */
	case 227: {
		struct freebsd64_msgrcv_args *p = params;
		iarg[0] = p->msqid; /* int */
		uarg[1] = (intptr_t) p->msgp; /* void * */
		uarg[2] = p->msgsz; /* size_t */
		iarg[3] = p->msgtyp; /* long */
		iarg[4] = p->msgflg; /* int */
		*n_args = 5;
		break;
	}
	/* freebsd64_shmat */
	case 228: {
		struct freebsd64_shmat_args *p = params;
		iarg[0] = p->shmid; /* int */
		uarg[1] = (intptr_t) p->shmaddr; /* const void * */
		iarg[2] = p->shmflg; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_shmdt */
	case 230: {
		struct freebsd64_shmdt_args *p = params;
		uarg[0] = (intptr_t) p->shmaddr; /* const void * */
		*n_args = 1;
		break;
	}
	/* shmget */
	case 231: {
		struct shmget_args *p = params;
		iarg[0] = p->key; /* key_t */
		uarg[1] = p->size; /* size_t */
		iarg[2] = p->shmflg; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_clock_gettime */
	case 232: {
		struct freebsd64_clock_gettime_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		uarg[1] = (intptr_t) p->tp; /* struct timespec * */
		*n_args = 2;
		break;
	}
	/* freebsd64_clock_settime */
	case 233: {
		struct freebsd64_clock_settime_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		uarg[1] = (intptr_t) p->tp; /* const struct timespec * */
		*n_args = 2;
		break;
	}
	/* freebsd64_clock_getres */
	case 234: {
		struct freebsd64_clock_getres_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		uarg[1] = (intptr_t) p->tp; /* struct timespec * */
		*n_args = 2;
		break;
	}
	/* freebsd64_ktimer_create */
	case 235: {
		struct freebsd64_ktimer_create_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		uarg[1] = (intptr_t) p->evp; /* struct sigevent64 * */
		uarg[2] = (intptr_t) p->timerid; /* int * */
		*n_args = 3;
		break;
	}
	/* ktimer_delete */
	case 236: {
		struct ktimer_delete_args *p = params;
		iarg[0] = p->timerid; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_ktimer_settime */
	case 237: {
		struct freebsd64_ktimer_settime_args *p = params;
		iarg[0] = p->timerid; /* int */
		iarg[1] = p->flags; /* int */
		uarg[2] = (intptr_t) p->value; /* const struct itimerspec * */
		uarg[3] = (intptr_t) p->ovalue; /* struct itimerspec * */
		*n_args = 4;
		break;
	}
	/* freebsd64_ktimer_gettime */
	case 238: {
		struct freebsd64_ktimer_gettime_args *p = params;
		iarg[0] = p->timerid; /* int */
		uarg[1] = (intptr_t) p->value; /* struct itimerspec * */
		*n_args = 2;
		break;
	}
	/* ktimer_getoverrun */
	case 239: {
		struct ktimer_getoverrun_args *p = params;
		iarg[0] = p->timerid; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_nanosleep */
	case 240: {
		struct freebsd64_nanosleep_args *p = params;
		uarg[0] = (intptr_t) p->rqtp; /* const struct timespec * */
		uarg[1] = (intptr_t) p->rmtp; /* struct timespec * */
		*n_args = 2;
		break;
	}
	/* freebsd64_ffclock_getcounter */
	case 241: {
		struct freebsd64_ffclock_getcounter_args *p = params;
		uarg[0] = (intptr_t) p->ffcount; /* ffcounter * */
		*n_args = 1;
		break;
	}
	/* freebsd64_ffclock_setestimate */
	case 242: {
		struct freebsd64_ffclock_setestimate_args *p = params;
		uarg[0] = (intptr_t) p->cest; /* struct ffclock_estimate * */
		*n_args = 1;
		break;
	}
	/* freebsd64_ffclock_getestimate */
	case 243: {
		struct freebsd64_ffclock_getestimate_args *p = params;
		uarg[0] = (intptr_t) p->cest; /* struct ffclock_estimate * */
		*n_args = 1;
		break;
	}
	/* freebsd64_clock_nanosleep */
	case 244: {
		struct freebsd64_clock_nanosleep_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		iarg[1] = p->flags; /* int */
		uarg[2] = (intptr_t) p->rqtp; /* const struct timespec * */
		uarg[3] = (intptr_t) p->rmtp; /* struct timespec * */
		*n_args = 4;
		break;
	}
	/* freebsd64_clock_getcpuclockid2 */
	case 247: {
		struct freebsd64_clock_getcpuclockid2_args *p = params;
		iarg[0] = p->id; /* id_t */
		iarg[1] = p->which; /* int */
		uarg[2] = (intptr_t) p->clock_id; /* clockid_t * */
		*n_args = 3;
		break;
	}
	/* freebsd64_ntp_gettime */
	case 248: {
		struct freebsd64_ntp_gettime_args *p = params;
		uarg[0] = (intptr_t) p->ntvp; /* struct ntptimeval * */
		*n_args = 1;
		break;
	}
	/* freebsd64_minherit */
	case 250: {
		struct freebsd64_minherit_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* void * */
		uarg[1] = p->len; /* size_t */
		iarg[2] = p->inherit; /* int */
		*n_args = 3;
		break;
	}
	/* rfork */
	case 251: {
		struct rfork_args *p = params;
		iarg[0] = p->flags; /* int */
		*n_args = 1;
		break;
	}
	/* issetugid */
	case 253: {
		*n_args = 0;
		break;
	}
	/* freebsd64_lchown */
	case 254: {
		struct freebsd64_lchown_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->uid; /* int */
		iarg[2] = p->gid; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_aio_read */
	case 255: {
		struct freebsd64_aio_read_args *p = params;
		uarg[0] = (intptr_t) p->aiocbp; /* struct aiocb64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64_aio_write */
	case 256: {
		struct freebsd64_aio_write_args *p = params;
		uarg[0] = (intptr_t) p->aiocbp; /* struct aiocb64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64_lio_listio */
	case 257: {
		struct freebsd64_lio_listio_args *p = params;
		iarg[0] = p->mode; /* int */
		uarg[1] = (intptr_t) p->acb_list; /* struct aiocb64 * const * */
		iarg[2] = p->nent; /* int */
		uarg[3] = (intptr_t) p->sig; /* struct sigevent64 * */
		*n_args = 4;
		break;
	}
	/* freebsd64_kbounce */
	case 258: {
		struct freebsd64_kbounce_args *p = params;
		uarg[0] = (intptr_t) p->src; /* const void * */
		uarg[1] = (intptr_t) p->dst; /* void * */
		uarg[2] = p->len; /* size_t */
		iarg[3] = p->flags; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_flag_captured */
	case 259: {
		struct freebsd64_flag_captured_args *p = params;
		uarg[0] = (intptr_t) p->message; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_lchmod */
	case 274: {
		struct freebsd64_lchmod_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_lutimes */
	case 276: {
		struct freebsd64_lutimes_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		uarg[1] = (intptr_t) p->tptr; /* const struct timeval * */
		*n_args = 2;
		break;
	}
	/* freebsd64_preadv */
	case 289: {
		struct freebsd64_preadv_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->iovp; /* struct iovec64 * */
		uarg[2] = p->iovcnt; /* u_int */
		iarg[3] = p->offset; /* off_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_pwritev */
	case 290: {
		struct freebsd64_pwritev_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->iovp; /* struct iovec64 * */
		uarg[2] = p->iovcnt; /* u_int */
		iarg[3] = p->offset; /* off_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_fhopen */
	case 298: {
		struct freebsd64_fhopen_args *p = params;
		uarg[0] = (intptr_t) p->u_fhp; /* const struct fhandle * */
		iarg[1] = p->flags; /* int */
		*n_args = 2;
		break;
	}
	/* modnext */
	case 300: {
		struct modnext_args *p = params;
		iarg[0] = p->modid; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_modstat */
	case 301: {
		struct freebsd64_modstat_args *p = params;
		iarg[0] = p->modid; /* int */
		uarg[1] = (intptr_t) p->stat; /* struct module_stat * */
		*n_args = 2;
		break;
	}
	/* modfnext */
	case 302: {
		struct modfnext_args *p = params;
		iarg[0] = p->modid; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_modfind */
	case 303: {
		struct freebsd64_modfind_args *p = params;
		uarg[0] = (intptr_t) p->name; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_kldload */
	case 304: {
		struct freebsd64_kldload_args *p = params;
		uarg[0] = (intptr_t) p->file; /* const char * */
		*n_args = 1;
		break;
	}
	/* kldunload */
	case 305: {
		struct kldunload_args *p = params;
		iarg[0] = p->fileid; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_kldfind */
	case 306: {
		struct freebsd64_kldfind_args *p = params;
		uarg[0] = (intptr_t) p->file; /* const char * */
		*n_args = 1;
		break;
	}
	/* kldnext */
	case 307: {
		struct kldnext_args *p = params;
		iarg[0] = p->fileid; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_kldstat */
	case 308: {
		struct freebsd64_kldstat_args *p = params;
		iarg[0] = p->fileid; /* int */
		uarg[1] = (intptr_t) p->stat; /* struct kld_file_stat64 * */
		*n_args = 2;
		break;
	}
	/* kldfirstmod */
	case 309: {
		struct kldfirstmod_args *p = params;
		iarg[0] = p->fileid; /* int */
		*n_args = 1;
		break;
	}
	/* getsid */
	case 310: {
		struct getsid_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		*n_args = 1;
		break;
	}
	/* setresuid */
	case 311: {
		struct setresuid_args *p = params;
		uarg[0] = p->ruid; /* uid_t */
		uarg[1] = p->euid; /* uid_t */
		uarg[2] = p->suid; /* uid_t */
		*n_args = 3;
		break;
	}
	/* setresgid */
	case 312: {
		struct setresgid_args *p = params;
		iarg[0] = p->rgid; /* gid_t */
		iarg[1] = p->egid; /* gid_t */
		iarg[2] = p->sgid; /* gid_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_aio_return */
	case 314: {
		struct freebsd64_aio_return_args *p = params;
		uarg[0] = (intptr_t) p->aiocbp; /* struct aiocb64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64_aio_suspend */
	case 315: {
		struct freebsd64_aio_suspend_args *p = params;
		uarg[0] = (intptr_t) p->aiocbp; /* struct aiocb64 * const * */
		iarg[1] = p->nent; /* int */
		uarg[2] = (intptr_t) p->timeout; /* const struct timespec * */
		*n_args = 3;
		break;
	}
	/* freebsd64_aio_cancel */
	case 316: {
		struct freebsd64_aio_cancel_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->aiocbp; /* struct aiocb64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64_aio_error */
	case 317: {
		struct freebsd64_aio_error_args *p = params;
		uarg[0] = (intptr_t) p->aiocbp; /* struct aiocb64 * */
		*n_args = 1;
		break;
	}
	/* yield */
	case 321: {
		*n_args = 0;
		break;
	}
	/* mlockall */
	case 324: {
		struct mlockall_args *p = params;
		iarg[0] = p->how; /* int */
		*n_args = 1;
		break;
	}
	/* munlockall */
	case 325: {
		*n_args = 0;
		break;
	}
	/* freebsd64___getcwd */
	case 326: {
		struct freebsd64___getcwd_args *p = params;
		uarg[0] = (intptr_t) p->buf; /* char * */
		uarg[1] = p->buflen; /* size_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_sched_setparam */
	case 327: {
		struct freebsd64_sched_setparam_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		uarg[1] = (intptr_t) p->param; /* const struct sched_param * */
		*n_args = 2;
		break;
	}
	/* freebsd64_sched_getparam */
	case 328: {
		struct freebsd64_sched_getparam_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		uarg[1] = (intptr_t) p->param; /* struct sched_param * */
		*n_args = 2;
		break;
	}
	/* freebsd64_sched_setscheduler */
	case 329: {
		struct freebsd64_sched_setscheduler_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		iarg[1] = p->policy; /* int */
		uarg[2] = (intptr_t) p->param; /* const struct sched_param * */
		*n_args = 3;
		break;
	}
	/* sched_getscheduler */
	case 330: {
		struct sched_getscheduler_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		*n_args = 1;
		break;
	}
	/* sched_yield */
	case 331: {
		*n_args = 0;
		break;
	}
	/* sched_get_priority_max */
	case 332: {
		struct sched_get_priority_max_args *p = params;
		iarg[0] = p->policy; /* int */
		*n_args = 1;
		break;
	}
	/* sched_get_priority_min */
	case 333: {
		struct sched_get_priority_min_args *p = params;
		iarg[0] = p->policy; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_sched_rr_get_interval */
	case 334: {
		struct freebsd64_sched_rr_get_interval_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		uarg[1] = (intptr_t) p->interval; /* struct timespec * */
		*n_args = 2;
		break;
	}
	/* freebsd64_utrace */
	case 335: {
		struct freebsd64_utrace_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* const void * */
		uarg[1] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_kldsym */
	case 337: {
		struct freebsd64_kldsym_args *p = params;
		iarg[0] = p->fileid; /* int */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (intptr_t) p->data; /* void * */
		*n_args = 3;
		break;
	}
	/* freebsd64_jail */
	case 338: {
		struct freebsd64_jail_args *p = params;
		uarg[0] = (intptr_t) p->jailp; /* struct jail64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64_nnpfs_syscall */
	case 339: {
		struct freebsd64_nnpfs_syscall_args *p = params;
		iarg[0] = p->operation; /* int */
		uarg[1] = (intptr_t) p->a_pathP; /* char * */
		iarg[2] = p->a_opcode; /* int */
		uarg[3] = (intptr_t) p->a_paramsP; /* void * */
		iarg[4] = p->a_followSymlinks; /* int */
		*n_args = 5;
		break;
	}
	/* freebsd64_sigprocmask */
	case 340: {
		struct freebsd64_sigprocmask_args *p = params;
		iarg[0] = p->how; /* int */
		uarg[1] = (intptr_t) p->set; /* const sigset_t * */
		uarg[2] = (intptr_t) p->oset; /* sigset_t * */
		*n_args = 3;
		break;
	}
	/* freebsd64_sigsuspend */
	case 341: {
		struct freebsd64_sigsuspend_args *p = params;
		uarg[0] = (intptr_t) p->sigmask; /* const sigset_t * */
		*n_args = 1;
		break;
	}
	/* freebsd64_sigpending */
	case 343: {
		struct freebsd64_sigpending_args *p = params;
		uarg[0] = (intptr_t) p->set; /* sigset_t * */
		*n_args = 1;
		break;
	}
	/* freebsd64_sigtimedwait */
	case 345: {
		struct freebsd64_sigtimedwait_args *p = params;
		uarg[0] = (intptr_t) p->set; /* const sigset_t * */
		uarg[1] = (intptr_t) p->info; /* struct siginfo64 * */
		uarg[2] = (intptr_t) p->timeout; /* const struct timespec * */
		*n_args = 3;
		break;
	}
	/* freebsd64_sigwaitinfo */
	case 346: {
		struct freebsd64_sigwaitinfo_args *p = params;
		uarg[0] = (intptr_t) p->set; /* const sigset_t * */
		uarg[1] = (intptr_t) p->info; /* struct siginfo64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64___acl_get_file */
	case 347: {
		struct freebsd64___acl_get_file_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64___acl_set_file */
	case 348: {
		struct freebsd64___acl_set_file_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64___acl_get_fd */
	case 349: {
		struct freebsd64___acl_get_fd_args *p = params;
		iarg[0] = p->filedes; /* int */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64___acl_set_fd */
	case 350: {
		struct freebsd64___acl_set_fd_args *p = params;
		iarg[0] = p->filedes; /* int */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64___acl_delete_file */
	case 351: {
		struct freebsd64___acl_delete_file_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->type; /* acl_type_t */
		*n_args = 2;
		break;
	}
	/* __acl_delete_fd */
	case 352: {
		struct __acl_delete_fd_args *p = params;
		iarg[0] = p->filedes; /* int */
		iarg[1] = p->type; /* acl_type_t */
		*n_args = 2;
		break;
	}
	/* freebsd64___acl_aclcheck_file */
	case 353: {
		struct freebsd64___acl_aclcheck_file_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64___acl_aclcheck_fd */
	case 354: {
		struct freebsd64___acl_aclcheck_fd_args *p = params;
		iarg[0] = p->filedes; /* int */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64_extattrctl */
	case 355: {
		struct freebsd64_extattrctl_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (intptr_t) p->filename; /* const char * */
		iarg[3] = p->attrnamespace; /* int */
		uarg[4] = (intptr_t) p->attrname; /* const char * */
		*n_args = 5;
		break;
	}
	/* freebsd64_extattr_set_file */
	case 356: {
		struct freebsd64_extattr_set_file_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		uarg[3] = (intptr_t) p->data; /* void * */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* freebsd64_extattr_get_file */
	case 357: {
		struct freebsd64_extattr_get_file_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		uarg[3] = (intptr_t) p->data; /* void * */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* freebsd64_extattr_delete_file */
	case 358: {
		struct freebsd64_extattr_delete_file_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		*n_args = 3;
		break;
	}
	/* freebsd64_aio_waitcomplete */
	case 359: {
		struct freebsd64_aio_waitcomplete_args *p = params;
		uarg[0] = (intptr_t) p->aiocbp; /* struct aiocb64 ** */
		uarg[1] = (intptr_t) p->timeout; /* struct timespec * */
		*n_args = 2;
		break;
	}
	/* freebsd64_getresuid */
	case 360: {
		struct freebsd64_getresuid_args *p = params;
		uarg[0] = (intptr_t) p->ruid; /* uid_t * */
		uarg[1] = (intptr_t) p->euid; /* uid_t * */
		uarg[2] = (intptr_t) p->suid; /* uid_t * */
		*n_args = 3;
		break;
	}
	/* freebsd64_getresgid */
	case 361: {
		struct freebsd64_getresgid_args *p = params;
		uarg[0] = (intptr_t) p->rgid; /* gid_t * */
		uarg[1] = (intptr_t) p->egid; /* gid_t * */
		uarg[2] = (intptr_t) p->sgid; /* gid_t * */
		*n_args = 3;
		break;
	}
	/* kqueue */
	case 362: {
		*n_args = 0;
		break;
	}
	/* freebsd64_extattr_set_fd */
	case 371: {
		struct freebsd64_extattr_set_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		uarg[3] = (intptr_t) p->data; /* void * */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* freebsd64_extattr_get_fd */
	case 372: {
		struct freebsd64_extattr_get_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		uarg[3] = (intptr_t) p->data; /* void * */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* freebsd64_extattr_delete_fd */
	case 373: {
		struct freebsd64_extattr_delete_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		*n_args = 3;
		break;
	}
	/* __setugid */
	case 374: {
		struct __setugid_args *p = params;
		iarg[0] = p->flag; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_eaccess */
	case 376: {
		struct freebsd64_eaccess_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->amode; /* int */
		*n_args = 2;
		break;
	}
	/* afs3_syscall */
	case 377: {
		struct afs3_syscall_args *p = params;
		iarg[0] = p->syscall; /* long */
		iarg[1] = p->parm1; /* long */
		iarg[2] = p->parm2; /* long */
		iarg[3] = p->parm3; /* long */
		iarg[4] = p->parm4; /* long */
		iarg[5] = p->parm5; /* long */
		iarg[6] = p->parm6; /* long */
		*n_args = 7;
		break;
	}
	/* freebsd64_nmount */
	case 378: {
		struct freebsd64_nmount_args *p = params;
		uarg[0] = (intptr_t) p->iovp; /* struct iovec64 * */
		uarg[1] = p->iovcnt; /* unsigned int */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64___mac_get_proc */
	case 384: {
		struct freebsd64___mac_get_proc_args *p = params;
		uarg[0] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64___mac_set_proc */
	case 385: {
		struct freebsd64___mac_set_proc_args *p = params;
		uarg[0] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64___mac_get_fd */
	case 386: {
		struct freebsd64___mac_get_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64___mac_get_file */
	case 387: {
		struct freebsd64___mac_get_file_args *p = params;
		uarg[0] = (intptr_t) p->path_p; /* const char * */
		uarg[1] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64___mac_set_fd */
	case 388: {
		struct freebsd64___mac_set_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64___mac_set_file */
	case 389: {
		struct freebsd64___mac_set_file_args *p = params;
		uarg[0] = (intptr_t) p->path_p; /* const char * */
		uarg[1] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64_kenv */
	case 390: {
		struct freebsd64_kenv_args *p = params;
		iarg[0] = p->what; /* int */
		uarg[1] = (intptr_t) p->name; /* const char * */
		uarg[2] = (intptr_t) p->value; /* char * */
		iarg[3] = p->len; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_lchflags */
	case 391: {
		struct freebsd64_lchflags_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		uarg[1] = p->flags; /* u_long */
		*n_args = 2;
		break;
	}
	/* freebsd64_uuidgen */
	case 392: {
		struct freebsd64_uuidgen_args *p = params;
		uarg[0] = (intptr_t) p->store; /* struct uuid * */
		iarg[1] = p->count; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_sendfile */
	case 393: {
		struct freebsd64_sendfile_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->s; /* int */
		iarg[2] = p->offset; /* off_t */
		uarg[3] = p->nbytes; /* size_t */
		uarg[4] = (intptr_t) p->hdtr; /* struct sf_hdtr64 * */
		uarg[5] = (intptr_t) p->sbytes; /* off_t * */
		iarg[6] = p->flags; /* int */
		*n_args = 7;
		break;
	}
	/* freebsd64_mac_syscall */
	case 394: {
		struct freebsd64_mac_syscall_args *p = params;
		uarg[0] = (intptr_t) p->policy; /* const char * */
		iarg[1] = p->call; /* int */
		uarg[2] = (intptr_t) p->arg; /* void * */
		*n_args = 3;
		break;
	}
	/* ksem_close */
	case 400: {
		struct ksem_close_args *p = params;
		iarg[0] = p->id; /* semid_t */
		*n_args = 1;
		break;
	}
	/* ksem_post */
	case 401: {
		struct ksem_post_args *p = params;
		iarg[0] = p->id; /* semid_t */
		*n_args = 1;
		break;
	}
	/* ksem_wait */
	case 402: {
		struct ksem_wait_args *p = params;
		iarg[0] = p->id; /* semid_t */
		*n_args = 1;
		break;
	}
	/* ksem_trywait */
	case 403: {
		struct ksem_trywait_args *p = params;
		iarg[0] = p->id; /* semid_t */
		*n_args = 1;
		break;
	}
	/* freebsd64_ksem_init */
	case 404: {
		struct freebsd64_ksem_init_args *p = params;
		uarg[0] = (intptr_t) p->idp; /* semid_t * */
		uarg[1] = p->value; /* unsigned int */
		*n_args = 2;
		break;
	}
	/* freebsd64_ksem_open */
	case 405: {
		struct freebsd64_ksem_open_args *p = params;
		uarg[0] = (intptr_t) p->idp; /* semid_t * */
		uarg[1] = (intptr_t) p->name; /* const char * */
		iarg[2] = p->oflag; /* int */
		iarg[3] = p->mode; /* mode_t */
		uarg[4] = p->value; /* unsigned int */
		*n_args = 5;
		break;
	}
	/* freebsd64_ksem_unlink */
	case 406: {
		struct freebsd64_ksem_unlink_args *p = params;
		uarg[0] = (intptr_t) p->name; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_ksem_getvalue */
	case 407: {
		struct freebsd64_ksem_getvalue_args *p = params;
		iarg[0] = p->id; /* semid_t */
		uarg[1] = (intptr_t) p->val; /* int * */
		*n_args = 2;
		break;
	}
	/* ksem_destroy */
	case 408: {
		struct ksem_destroy_args *p = params;
		iarg[0] = p->id; /* semid_t */
		*n_args = 1;
		break;
	}
	/* freebsd64___mac_get_pid */
	case 409: {
		struct freebsd64___mac_get_pid_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		uarg[1] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64___mac_get_link */
	case 410: {
		struct freebsd64___mac_get_link_args *p = params;
		uarg[0] = (intptr_t) p->path_p; /* const char * */
		uarg[1] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64___mac_set_link */
	case 411: {
		struct freebsd64___mac_set_link_args *p = params;
		uarg[0] = (intptr_t) p->path_p; /* const char * */
		uarg[1] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64_extattr_set_link */
	case 412: {
		struct freebsd64_extattr_set_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		uarg[3] = (intptr_t) p->data; /* void * */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* freebsd64_extattr_get_link */
	case 413: {
		struct freebsd64_extattr_get_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		uarg[3] = (intptr_t) p->data; /* void * */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* freebsd64_extattr_delete_link */
	case 414: {
		struct freebsd64_extattr_delete_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->attrname; /* const char * */
		*n_args = 3;
		break;
	}
	/* freebsd64___mac_execve */
	case 415: {
		struct freebsd64___mac_execve_args *p = params;
		uarg[0] = (intptr_t) p->fname; /* const char * */
		uarg[1] = (intptr_t) p->argv; /* char ** */
		uarg[2] = (intptr_t) p->envv; /* char ** */
		uarg[3] = (intptr_t) p->mac_p; /* struct mac64 * */
		*n_args = 4;
		break;
	}
	/* freebsd64_sigaction */
	case 416: {
		struct freebsd64_sigaction_args *p = params;
		iarg[0] = p->sig; /* int */
		uarg[1] = (intptr_t) p->act; /* const struct sigaction64 * */
		uarg[2] = (intptr_t) p->oact; /* struct sigaction64 * */
		*n_args = 3;
		break;
	}
	/* freebsd64_sigreturn */
	case 417: {
		struct freebsd64_sigreturn_args *p = params;
		uarg[0] = (intptr_t) p->sigcntxp; /* const struct __ucontext64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64_getcontext */
	case 421: {
		struct freebsd64_getcontext_args *p = params;
		uarg[0] = (intptr_t) p->ucp; /* struct __ucontext64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64_setcontext */
	case 422: {
		struct freebsd64_setcontext_args *p = params;
		uarg[0] = (intptr_t) p->ucp; /* const struct __ucontext64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64_swapcontext */
	case 423: {
		struct freebsd64_swapcontext_args *p = params;
		uarg[0] = (intptr_t) p->oucp; /* struct __ucontext64 * */
		uarg[1] = (intptr_t) p->ucp; /* const struct __ucontext64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64_swapoff */
	case 424: {
		struct freebsd64_swapoff_args *p = params;
		uarg[0] = (intptr_t) p->name; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64___acl_get_link */
	case 425: {
		struct freebsd64___acl_get_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64___acl_set_link */
	case 426: {
		struct freebsd64___acl_set_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64___acl_delete_link */
	case 427: {
		struct freebsd64___acl_delete_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->type; /* acl_type_t */
		*n_args = 2;
		break;
	}
	/* freebsd64___acl_aclcheck_link */
	case 428: {
		struct freebsd64___acl_aclcheck_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (intptr_t) p->aclp; /* struct acl * */
		*n_args = 3;
		break;
	}
	/* freebsd64_sigwait */
	case 429: {
		struct freebsd64_sigwait_args *p = params;
		uarg[0] = (intptr_t) p->set; /* const sigset_t * */
		uarg[1] = (intptr_t) p->sig; /* int * */
		*n_args = 2;
		break;
	}
	/* freebsd64_thr_create */
	case 430: {
		struct freebsd64_thr_create_args *p = params;
		uarg[0] = (intptr_t) p->ctx; /* struct __ucontext64 * */
		uarg[1] = (intptr_t) p->id; /* long * */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_thr_exit */
	case 431: {
		struct freebsd64_thr_exit_args *p = params;
		uarg[0] = (intptr_t) p->state; /* long * */
		*n_args = 1;
		break;
	}
	/* freebsd64_thr_self */
	case 432: {
		struct freebsd64_thr_self_args *p = params;
		uarg[0] = (intptr_t) p->id; /* long * */
		*n_args = 1;
		break;
	}
	/* thr_kill */
	case 433: {
		struct thr_kill_args *p = params;
		iarg[0] = p->id; /* long */
		iarg[1] = p->sig; /* int */
		*n_args = 2;
		break;
	}
	/* jail_attach */
	case 436: {
		struct jail_attach_args *p = params;
		iarg[0] = p->jid; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_extattr_list_fd */
	case 437: {
		struct freebsd64_extattr_list_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->data; /* void * */
		uarg[3] = p->nbytes; /* size_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_extattr_list_file */
	case 438: {
		struct freebsd64_extattr_list_file_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->data; /* void * */
		uarg[3] = p->nbytes; /* size_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_extattr_list_link */
	case 439: {
		struct freebsd64_extattr_list_link_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (intptr_t) p->data; /* void * */
		uarg[3] = p->nbytes; /* size_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_ksem_timedwait */
	case 441: {
		struct freebsd64_ksem_timedwait_args *p = params;
		iarg[0] = p->id; /* semid_t */
		uarg[1] = (intptr_t) p->abstime; /* const struct timespec * */
		*n_args = 2;
		break;
	}
	/* freebsd64_thr_suspend */
	case 442: {
		struct freebsd64_thr_suspend_args *p = params;
		uarg[0] = (intptr_t) p->timeout; /* const struct timespec * */
		*n_args = 1;
		break;
	}
	/* thr_wake */
	case 443: {
		struct thr_wake_args *p = params;
		iarg[0] = p->id; /* long */
		*n_args = 1;
		break;
	}
	/* kldunloadf */
	case 444: {
		struct kldunloadf_args *p = params;
		iarg[0] = p->fileid; /* int */
		iarg[1] = p->flags; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_audit */
	case 445: {
		struct freebsd64_audit_args *p = params;
		uarg[0] = (intptr_t) p->record; /* const void * */
		uarg[1] = p->length; /* u_int */
		*n_args = 2;
		break;
	}
	/* freebsd64_auditon */
	case 446: {
		struct freebsd64_auditon_args *p = params;
		iarg[0] = p->cmd; /* int */
		uarg[1] = (intptr_t) p->data; /* void * */
		uarg[2] = p->length; /* u_int */
		*n_args = 3;
		break;
	}
	/* freebsd64_getauid */
	case 447: {
		struct freebsd64_getauid_args *p = params;
		uarg[0] = (intptr_t) p->auid; /* uid_t * */
		*n_args = 1;
		break;
	}
	/* freebsd64_setauid */
	case 448: {
		struct freebsd64_setauid_args *p = params;
		uarg[0] = (intptr_t) p->auid; /* uid_t * */
		*n_args = 1;
		break;
	}
	/* freebsd64_getaudit */
	case 449: {
		struct freebsd64_getaudit_args *p = params;
		uarg[0] = (intptr_t) p->auditinfo; /* struct auditinfo * */
		*n_args = 1;
		break;
	}
	/* freebsd64_setaudit */
	case 450: {
		struct freebsd64_setaudit_args *p = params;
		uarg[0] = (intptr_t) p->auditinfo; /* struct auditinfo * */
		*n_args = 1;
		break;
	}
	/* freebsd64_getaudit_addr */
	case 451: {
		struct freebsd64_getaudit_addr_args *p = params;
		uarg[0] = (intptr_t) p->auditinfo_addr; /* struct auditinfo_addr * */
		uarg[1] = p->length; /* u_int */
		*n_args = 2;
		break;
	}
	/* freebsd64_setaudit_addr */
	case 452: {
		struct freebsd64_setaudit_addr_args *p = params;
		uarg[0] = (intptr_t) p->auditinfo_addr; /* struct auditinfo_addr * */
		uarg[1] = p->length; /* u_int */
		*n_args = 2;
		break;
	}
	/* freebsd64_auditctl */
	case 453: {
		struct freebsd64_auditctl_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64__umtx_op */
	case 454: {
		struct freebsd64__umtx_op_args *p = params;
		uarg[0] = (intptr_t) p->obj; /* void * */
		iarg[1] = p->op; /* int */
		uarg[2] = p->val; /* u_long */
		uarg[3] = (intptr_t) p->uaddr1; /* void * */
		uarg[4] = (intptr_t) p->uaddr2; /* void * */
		*n_args = 5;
		break;
	}
	/* freebsd64_thr_new */
	case 455: {
		struct freebsd64_thr_new_args *p = params;
		uarg[0] = (intptr_t) p->param; /* struct thr_param64 * */
		iarg[1] = p->param_size; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_sigqueue */
	case 456: {
		struct freebsd64_sigqueue_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		iarg[1] = p->signum; /* int */
		uarg[2] = (intptr_t) p->value; /* void * */
		*n_args = 3;
		break;
	}
	/* freebsd64_kmq_open */
	case 457: {
		struct freebsd64_kmq_open_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->flags; /* int */
		iarg[2] = p->mode; /* mode_t */
		uarg[3] = (intptr_t) p->attr; /* const struct mq_attr * */
		*n_args = 4;
		break;
	}
	/* freebsd64_kmq_setattr */
	case 458: {
		struct freebsd64_kmq_setattr_args *p = params;
		iarg[0] = p->mqd; /* int */
		uarg[1] = (intptr_t) p->attr; /* const struct mq_attr * */
		uarg[2] = (intptr_t) p->oattr; /* struct mq_attr * */
		*n_args = 3;
		break;
	}
	/* freebsd64_kmq_timedreceive */
	case 459: {
		struct freebsd64_kmq_timedreceive_args *p = params;
		iarg[0] = p->mqd; /* int */
		uarg[1] = (intptr_t) p->msg_ptr; /* char * */
		uarg[2] = p->msg_len; /* size_t */
		uarg[3] = (intptr_t) p->msg_prio; /* unsigned * */
		uarg[4] = (intptr_t) p->abs_timeout; /* const struct timespec * */
		*n_args = 5;
		break;
	}
	/* freebsd64_kmq_timedsend */
	case 460: {
		struct freebsd64_kmq_timedsend_args *p = params;
		iarg[0] = p->mqd; /* int */
		uarg[1] = (intptr_t) p->msg_ptr; /* const char * */
		uarg[2] = p->msg_len; /* size_t */
		uarg[3] = p->msg_prio; /* unsigned */
		uarg[4] = (intptr_t) p->abs_timeout; /* const struct timespec * */
		*n_args = 5;
		break;
	}
	/* freebsd64_kmq_notify */
	case 461: {
		struct freebsd64_kmq_notify_args *p = params;
		iarg[0] = p->mqd; /* int */
		uarg[1] = (intptr_t) p->sigev; /* const struct sigevent64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64_kmq_unlink */
	case 462: {
		struct freebsd64_kmq_unlink_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_abort2 */
	case 463: {
		struct freebsd64_abort2_args *p = params;
		uarg[0] = (intptr_t) p->why; /* const char * */
		iarg[1] = p->nargs; /* int */
		uarg[2] = (intptr_t) p->args; /* void ** */
		*n_args = 3;
		break;
	}
	/* freebsd64_thr_set_name */
	case 464: {
		struct freebsd64_thr_set_name_args *p = params;
		iarg[0] = p->id; /* long */
		uarg[1] = (intptr_t) p->name; /* const char * */
		*n_args = 2;
		break;
	}
	/* freebsd64_aio_fsync */
	case 465: {
		struct freebsd64_aio_fsync_args *p = params;
		iarg[0] = p->op; /* int */
		uarg[1] = (intptr_t) p->aiocbp; /* struct aiocb64 * */
		*n_args = 2;
		break;
	}
	/* freebsd64_rtprio_thread */
	case 466: {
		struct freebsd64_rtprio_thread_args *p = params;
		iarg[0] = p->function; /* int */
		iarg[1] = p->lwpid; /* lwpid_t */
		uarg[2] = (intptr_t) p->rtp; /* struct rtprio * */
		*n_args = 3;
		break;
	}
	/* sctp_peeloff */
	case 471: {
		struct sctp_peeloff_args *p = params;
		iarg[0] = p->sd; /* int */
		uarg[1] = p->name; /* uint32_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_sctp_generic_sendmsg */
	case 472: {
		struct freebsd64_sctp_generic_sendmsg_args *p = params;
		iarg[0] = p->sd; /* int */
		uarg[1] = (intptr_t) p->msg; /* void * */
		iarg[2] = p->mlen; /* int */
		uarg[3] = (intptr_t) p->to; /* const struct sockaddr * */
		iarg[4] = p->tolen; /* __socklen_t */
		uarg[5] = (intptr_t) p->sinfo; /* struct sctp_sndrcvinfo * */
		iarg[6] = p->flags; /* int */
		*n_args = 7;
		break;
	}
	/* freebsd64_sctp_generic_sendmsg_iov */
	case 473: {
		struct freebsd64_sctp_generic_sendmsg_iov_args *p = params;
		iarg[0] = p->sd; /* int */
		uarg[1] = (intptr_t) p->iov; /* struct iovec64 * */
		iarg[2] = p->iovlen; /* int */
		uarg[3] = (intptr_t) p->to; /* const struct sockaddr * */
		iarg[4] = p->tolen; /* __socklen_t */
		uarg[5] = (intptr_t) p->sinfo; /* struct sctp_sndrcvinfo * */
		iarg[6] = p->flags; /* int */
		*n_args = 7;
		break;
	}
	/* freebsd64_sctp_generic_recvmsg */
	case 474: {
		struct freebsd64_sctp_generic_recvmsg_args *p = params;
		iarg[0] = p->sd; /* int */
		uarg[1] = (intptr_t) p->iov; /* struct iovec64 * */
		iarg[2] = p->iovlen; /* int */
		uarg[3] = (intptr_t) p->from; /* struct sockaddr * */
		uarg[4] = (intptr_t) p->fromlenaddr; /* __socklen_t * */
		uarg[5] = (intptr_t) p->sinfo; /* struct sctp_sndrcvinfo * */
		uarg[6] = (intptr_t) p->msg_flags; /* int * */
		*n_args = 7;
		break;
	}
	/* freebsd64_pread */
	case 475: {
		struct freebsd64_pread_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->buf; /* void * */
		uarg[2] = p->nbyte; /* size_t */
		iarg[3] = p->offset; /* off_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_pwrite */
	case 476: {
		struct freebsd64_pwrite_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->buf; /* const void * */
		uarg[2] = p->nbyte; /* size_t */
		iarg[3] = p->offset; /* off_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_mmap */
	case 477: {
		struct freebsd64_mmap_args *p = params;
		uarg[0] = (intptr_t) p->addr; /* void * */
		uarg[1] = p->len; /* size_t */
		iarg[2] = p->prot; /* int */
		iarg[3] = p->flags; /* int */
		iarg[4] = p->fd; /* int */
		iarg[5] = p->pos; /* off_t */
		*n_args = 6;
		break;
	}
	/* lseek */
	case 478: {
		struct lseek_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->offset; /* off_t */
		iarg[2] = p->whence; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_truncate */
	case 479: {
		struct freebsd64_truncate_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->length; /* off_t */
		*n_args = 2;
		break;
	}
	/* ftruncate */
	case 480: {
		struct ftruncate_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->length; /* off_t */
		*n_args = 2;
		break;
	}
	/* thr_kill2 */
	case 481: {
		struct thr_kill2_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		iarg[1] = p->id; /* long */
		iarg[2] = p->sig; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_shm_unlink */
	case 483: {
		struct freebsd64_shm_unlink_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_cpuset */
	case 484: {
		struct freebsd64_cpuset_args *p = params;
		uarg[0] = (intptr_t) p->setid; /* cpusetid_t * */
		*n_args = 1;
		break;
	}
	/* cpuset_setid */
	case 485: {
		struct cpuset_setid_args *p = params;
		iarg[0] = p->which; /* cpuwhich_t */
		iarg[1] = p->id; /* id_t */
		iarg[2] = p->setid; /* cpusetid_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_cpuset_getid */
	case 486: {
		struct freebsd64_cpuset_getid_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = (intptr_t) p->setid; /* cpusetid_t * */
		*n_args = 4;
		break;
	}
	/* freebsd64_cpuset_getaffinity */
	case 487: {
		struct freebsd64_cpuset_getaffinity_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = p->cpusetsize; /* size_t */
		uarg[4] = (intptr_t) p->mask; /* cpuset_t * */
		*n_args = 5;
		break;
	}
	/* freebsd64_cpuset_setaffinity */
	case 488: {
		struct freebsd64_cpuset_setaffinity_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = p->cpusetsize; /* size_t */
		uarg[4] = (intptr_t) p->mask; /* const cpuset_t * */
		*n_args = 5;
		break;
	}
	/* freebsd64_faccessat */
	case 489: {
		struct freebsd64_faccessat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->amode; /* int */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_fchmodat */
	case 490: {
		struct freebsd64_fchmodat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->mode; /* mode_t */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_fchownat */
	case 491: {
		struct freebsd64_fchownat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		uarg[2] = p->uid; /* uid_t */
		iarg[3] = p->gid; /* gid_t */
		iarg[4] = p->flag; /* int */
		*n_args = 5;
		break;
	}
	/* freebsd64_fexecve */
	case 492: {
		struct freebsd64_fexecve_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->argv; /* char ** */
		uarg[2] = (intptr_t) p->envv; /* char ** */
		*n_args = 3;
		break;
	}
	/* freebsd64_futimesat */
	case 494: {
		struct freebsd64_futimesat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		uarg[2] = (intptr_t) p->times; /* const struct timeval * */
		*n_args = 3;
		break;
	}
	/* freebsd64_linkat */
	case 495: {
		struct freebsd64_linkat_args *p = params;
		iarg[0] = p->fd1; /* int */
		uarg[1] = (intptr_t) p->path1; /* const char * */
		iarg[2] = p->fd2; /* int */
		uarg[3] = (intptr_t) p->path2; /* const char * */
		iarg[4] = p->flag; /* int */
		*n_args = 5;
		break;
	}
	/* freebsd64_mkdirat */
	case 496: {
		struct freebsd64_mkdirat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->mode; /* mode_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_mkfifoat */
	case 497: {
		struct freebsd64_mkfifoat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->mode; /* mode_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_openat */
	case 499: {
		struct freebsd64_openat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->flag; /* int */
		iarg[3] = p->mode; /* mode_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_readlinkat */
	case 500: {
		struct freebsd64_readlinkat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		uarg[2] = (intptr_t) p->buf; /* char * */
		uarg[3] = p->bufsize; /* size_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_renameat */
	case 501: {
		struct freebsd64_renameat_args *p = params;
		iarg[0] = p->oldfd; /* int */
		uarg[1] = (intptr_t) p->old; /* const char * */
		iarg[2] = p->newfd; /* int */
		uarg[3] = (intptr_t) p->new; /* const char * */
		*n_args = 4;
		break;
	}
	/* freebsd64_symlinkat */
	case 502: {
		struct freebsd64_symlinkat_args *p = params;
		uarg[0] = (intptr_t) p->path1; /* const char * */
		iarg[1] = p->fd; /* int */
		uarg[2] = (intptr_t) p->path2; /* const char * */
		*n_args = 3;
		break;
	}
	/* freebsd64_unlinkat */
	case 503: {
		struct freebsd64_unlinkat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->flag; /* int */
		*n_args = 3;
		break;
	}
	/* posix_openpt */
	case 504: {
		struct posix_openpt_args *p = params;
		iarg[0] = p->flags; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_gssd_syscall */
	case 505: {
		struct freebsd64_gssd_syscall_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_jail_get */
	case 506: {
		struct freebsd64_jail_get_args *p = params;
		uarg[0] = (intptr_t) p->iovp; /* struct iovec64 * */
		uarg[1] = p->iovcnt; /* unsigned int */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_jail_set */
	case 507: {
		struct freebsd64_jail_set_args *p = params;
		uarg[0] = (intptr_t) p->iovp; /* struct iovec64 * */
		uarg[1] = p->iovcnt; /* unsigned int */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* jail_remove */
	case 508: {
		struct jail_remove_args *p = params;
		iarg[0] = p->jid; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64___semctl */
	case 510: {
		struct freebsd64___semctl_args *p = params;
		iarg[0] = p->semid; /* int */
		iarg[1] = p->semnum; /* int */
		iarg[2] = p->cmd; /* int */
		uarg[3] = (intptr_t) p->arg; /* union semun64 * */
		*n_args = 4;
		break;
	}
	/* freebsd64_msgctl */
	case 511: {
		struct freebsd64_msgctl_args *p = params;
		iarg[0] = p->msqid; /* int */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (intptr_t) p->buf; /* struct msqid_ds64 * */
		*n_args = 3;
		break;
	}
	/* freebsd64_shmctl */
	case 512: {
		struct freebsd64_shmctl_args *p = params;
		iarg[0] = p->shmid; /* int */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (intptr_t) p->buf; /* struct shmid_ds * */
		*n_args = 3;
		break;
	}
	/* freebsd64_lpathconf */
	case 513: {
		struct freebsd64_lpathconf_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->name; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64___cap_rights_get */
	case 515: {
		struct freebsd64___cap_rights_get_args *p = params;
		iarg[0] = p->version; /* int */
		iarg[1] = p->fd; /* int */
		uarg[2] = (intptr_t) p->rightsp; /* cap_rights_t * */
		*n_args = 3;
		break;
	}
	/* cap_enter */
	case 516: {
		*n_args = 0;
		break;
	}
	/* freebsd64_cap_getmode */
	case 517: {
		struct freebsd64_cap_getmode_args *p = params;
		uarg[0] = (intptr_t) p->modep; /* u_int * */
		*n_args = 1;
		break;
	}
	/* freebsd64_pdfork */
	case 518: {
		struct freebsd64_pdfork_args *p = params;
		uarg[0] = (intptr_t) p->fdp; /* int * */
		iarg[1] = p->flags; /* int */
		*n_args = 2;
		break;
	}
	/* pdkill */
	case 519: {
		struct pdkill_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->signum; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_pdgetpid */
	case 520: {
		struct freebsd64_pdgetpid_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->pidp; /* pid_t * */
		*n_args = 2;
		break;
	}
	/* freebsd64_pselect */
	case 522: {
		struct freebsd64_pselect_args *p = params;
		iarg[0] = p->nd; /* int */
		uarg[1] = (intptr_t) p->in; /* fd_set * */
		uarg[2] = (intptr_t) p->ou; /* fd_set * */
		uarg[3] = (intptr_t) p->ex; /* fd_set * */
		uarg[4] = (intptr_t) p->ts; /* const struct timespec * */
		uarg[5] = (intptr_t) p->sm; /* const sigset_t * */
		*n_args = 6;
		break;
	}
	/* freebsd64_getloginclass */
	case 523: {
		struct freebsd64_getloginclass_args *p = params;
		uarg[0] = (intptr_t) p->namebuf; /* char * */
		uarg[1] = p->namelen; /* size_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_setloginclass */
	case 524: {
		struct freebsd64_setloginclass_args *p = params;
		uarg[0] = (intptr_t) p->namebuf; /* const char * */
		*n_args = 1;
		break;
	}
	/* freebsd64_rctl_get_racct */
	case 525: {
		struct freebsd64_rctl_get_racct_args *p = params;
		uarg[0] = (intptr_t) p->inbufp; /* const void * */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (intptr_t) p->outbufp; /* void * */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_rctl_get_rules */
	case 526: {
		struct freebsd64_rctl_get_rules_args *p = params;
		uarg[0] = (intptr_t) p->inbufp; /* const void * */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (intptr_t) p->outbufp; /* void * */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_rctl_get_limits */
	case 527: {
		struct freebsd64_rctl_get_limits_args *p = params;
		uarg[0] = (intptr_t) p->inbufp; /* const void * */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (intptr_t) p->outbufp; /* void * */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_rctl_add_rule */
	case 528: {
		struct freebsd64_rctl_add_rule_args *p = params;
		uarg[0] = (intptr_t) p->inbufp; /* const void * */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (intptr_t) p->outbufp; /* void * */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_rctl_remove_rule */
	case 529: {
		struct freebsd64_rctl_remove_rule_args *p = params;
		uarg[0] = (intptr_t) p->inbufp; /* const void * */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (intptr_t) p->outbufp; /* void * */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* posix_fallocate */
	case 530: {
		struct posix_fallocate_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->offset; /* off_t */
		iarg[2] = p->len; /* off_t */
		*n_args = 3;
		break;
	}
	/* posix_fadvise */
	case 531: {
		struct posix_fadvise_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->offset; /* off_t */
		iarg[2] = p->len; /* off_t */
		iarg[3] = p->advice; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_wait6 */
	case 532: {
		struct freebsd64_wait6_args *p = params;
		iarg[0] = p->idtype; /* idtype_t */
		iarg[1] = p->id; /* id_t */
		uarg[2] = (intptr_t) p->status; /* int * */
		iarg[3] = p->options; /* int */
		uarg[4] = (intptr_t) p->wrusage; /* struct __wrusage * */
		uarg[5] = (intptr_t) p->info; /* struct siginfo64 * */
		*n_args = 6;
		break;
	}
	/* freebsd64_cap_rights_limit */
	case 533: {
		struct freebsd64_cap_rights_limit_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->rightsp; /* cap_rights_t * */
		*n_args = 2;
		break;
	}
	/* freebsd64_cap_ioctls_limit */
	case 534: {
		struct freebsd64_cap_ioctls_limit_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->cmds; /* const u_long * */
		uarg[2] = p->ncmds; /* size_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_cap_ioctls_get */
	case 535: {
		struct freebsd64_cap_ioctls_get_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->cmds; /* u_long * */
		uarg[2] = p->maxcmds; /* size_t */
		*n_args = 3;
		break;
	}
	/* cap_fcntls_limit */
	case 536: {
		struct cap_fcntls_limit_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = p->fcntlrights; /* uint32_t */
		*n_args = 2;
		break;
	}
	/* freebsd64_cap_fcntls_get */
	case 537: {
		struct freebsd64_cap_fcntls_get_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->fcntlrightsp; /* uint32_t * */
		*n_args = 2;
		break;
	}
	/* freebsd64_bindat */
	case 538: {
		struct freebsd64_bindat_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->s; /* int */
		uarg[2] = (intptr_t) p->name; /* const struct sockaddr * */
		iarg[3] = p->namelen; /* __socklen_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_connectat */
	case 539: {
		struct freebsd64_connectat_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->s; /* int */
		uarg[2] = (intptr_t) p->name; /* const struct sockaddr * */
		iarg[3] = p->namelen; /* __socklen_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_chflagsat */
	case 540: {
		struct freebsd64_chflagsat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		uarg[2] = p->flags; /* u_long */
		iarg[3] = p->atflag; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_accept4 */
	case 541: {
		struct freebsd64_accept4_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (intptr_t) p->name; /* struct sockaddr * */
		uarg[2] = (intptr_t) p->anamelen; /* __socklen_t * */
		iarg[3] = p->flags; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_pipe2 */
	case 542: {
		struct freebsd64_pipe2_args *p = params;
		uarg[0] = (intptr_t) p->fildes; /* int * */
		iarg[1] = p->flags; /* int */
		*n_args = 2;
		break;
	}
	/* freebsd64_aio_mlock */
	case 543: {
		struct freebsd64_aio_mlock_args *p = params;
		uarg[0] = (intptr_t) p->aiocbp; /* struct aiocb64 * */
		*n_args = 1;
		break;
	}
	/* freebsd64_procctl */
	case 544: {
		struct freebsd64_procctl_args *p = params;
		iarg[0] = p->idtype; /* idtype_t */
		iarg[1] = p->id; /* id_t */
		iarg[2] = p->com; /* int */
		uarg[3] = (intptr_t) p->data; /* void * */
		*n_args = 4;
		break;
	}
	/* freebsd64_ppoll */
	case 545: {
		struct freebsd64_ppoll_args *p = params;
		uarg[0] = (intptr_t) p->fds; /* struct pollfd * */
		uarg[1] = p->nfds; /* u_int */
		uarg[2] = (intptr_t) p->ts; /* const struct timespec * */
		uarg[3] = (intptr_t) p->set; /* const sigset_t * */
		*n_args = 4;
		break;
	}
	/* freebsd64_futimens */
	case 546: {
		struct freebsd64_futimens_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->times; /* const struct timespec * */
		*n_args = 2;
		break;
	}
	/* freebsd64_utimensat */
	case 547: {
		struct freebsd64_utimensat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		uarg[2] = (intptr_t) p->times; /* const struct timespec * */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* fdatasync */
	case 550: {
		struct fdatasync_args *p = params;
		iarg[0] = p->fd; /* int */
		*n_args = 1;
		break;
	}
	/* freebsd64_fstat */
	case 551: {
		struct freebsd64_fstat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->sb; /* struct stat * */
		*n_args = 2;
		break;
	}
	/* freebsd64_fstatat */
	case 552: {
		struct freebsd64_fstatat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		uarg[2] = (intptr_t) p->buf; /* struct stat * */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_fhstat */
	case 553: {
		struct freebsd64_fhstat_args *p = params;
		uarg[0] = (intptr_t) p->u_fhp; /* const struct fhandle * */
		uarg[1] = (intptr_t) p->sb; /* struct stat * */
		*n_args = 2;
		break;
	}
	/* freebsd64_getdirentries */
	case 554: {
		struct freebsd64_getdirentries_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->buf; /* char * */
		uarg[2] = p->count; /* size_t */
		uarg[3] = (intptr_t) p->basep; /* off_t * */
		*n_args = 4;
		break;
	}
	/* freebsd64_statfs */
	case 555: {
		struct freebsd64_statfs_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		uarg[1] = (intptr_t) p->buf; /* struct statfs * */
		*n_args = 2;
		break;
	}
	/* freebsd64_fstatfs */
	case 556: {
		struct freebsd64_fstatfs_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->buf; /* struct statfs * */
		*n_args = 2;
		break;
	}
	/* freebsd64_getfsstat */
	case 557: {
		struct freebsd64_getfsstat_args *p = params;
		uarg[0] = (intptr_t) p->buf; /* struct statfs * */
		iarg[1] = p->bufsize; /* long */
		iarg[2] = p->mode; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_fhstatfs */
	case 558: {
		struct freebsd64_fhstatfs_args *p = params;
		uarg[0] = (intptr_t) p->u_fhp; /* const struct fhandle * */
		uarg[1] = (intptr_t) p->buf; /* struct statfs * */
		*n_args = 2;
		break;
	}
	/* freebsd64_mknodat */
	case 559: {
		struct freebsd64_mknodat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->mode; /* mode_t */
		iarg[3] = p->dev; /* dev_t */
		*n_args = 4;
		break;
	}
	/* freebsd64_kevent */
	case 560: {
		struct freebsd64_kevent_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->changelist; /* const struct kevent64 * */
		iarg[2] = p->nchanges; /* int */
		uarg[3] = (intptr_t) p->eventlist; /* struct kevent64 * */
		iarg[4] = p->nevents; /* int */
		uarg[5] = (intptr_t) p->timeout; /* const struct timespec * */
		*n_args = 6;
		break;
	}
	/* freebsd64_cpuset_getdomain */
	case 561: {
		struct freebsd64_cpuset_getdomain_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = p->domainsetsize; /* size_t */
		uarg[4] = (intptr_t) p->mask; /* domainset_t * */
		uarg[5] = (intptr_t) p->policy; /* int * */
		*n_args = 6;
		break;
	}
	/* freebsd64_cpuset_setdomain */
	case 562: {
		struct freebsd64_cpuset_setdomain_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = p->domainsetsize; /* size_t */
		uarg[4] = (intptr_t) p->mask; /* domainset_t * */
		iarg[5] = p->policy; /* int */
		*n_args = 6;
		break;
	}
	/* freebsd64_getrandom */
	case 563: {
		struct freebsd64_getrandom_args *p = params;
		uarg[0] = (intptr_t) p->buf; /* void * */
		uarg[1] = p->buflen; /* size_t */
		uarg[2] = p->flags; /* unsigned int */
		*n_args = 3;
		break;
	}
	/* freebsd64_getfhat */
	case 564: {
		struct freebsd64_getfhat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* char * */
		uarg[2] = (intptr_t) p->fhp; /* struct fhandle * */
		iarg[3] = p->flags; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_fhlink */
	case 565: {
		struct freebsd64_fhlink_args *p = params;
		uarg[0] = (intptr_t) p->fhp; /* struct fhandle * */
		uarg[1] = (intptr_t) p->to; /* const char * */
		*n_args = 2;
		break;
	}
	/* freebsd64_fhlinkat */
	case 566: {
		struct freebsd64_fhlinkat_args *p = params;
		uarg[0] = (intptr_t) p->fhp; /* struct fhandle * */
		iarg[1] = p->tofd; /* int */
		uarg[2] = (intptr_t) p->to; /* const char * */
		*n_args = 3;
		break;
	}
	/* freebsd64_fhreadlink */
	case 567: {
		struct freebsd64_fhreadlink_args *p = params;
		uarg[0] = (intptr_t) p->fhp; /* struct fhandle * */
		uarg[1] = (intptr_t) p->buf; /* char * */
		uarg[2] = p->bufsize; /* size_t */
		*n_args = 3;
		break;
	}
	/* freebsd64_funlinkat */
	case 568: {
		struct freebsd64_funlinkat_args *p = params;
		iarg[0] = p->dfd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		iarg[2] = p->fd; /* int */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* freebsd64_copy_file_range */
	case 569: {
		struct freebsd64_copy_file_range_args *p = params;
		iarg[0] = p->infd; /* int */
		uarg[1] = (intptr_t) p->inoffp; /* off_t * */
		iarg[2] = p->outfd; /* int */
		uarg[3] = (intptr_t) p->outoffp; /* off_t * */
		uarg[4] = p->len; /* size_t */
		uarg[5] = p->flags; /* unsigned int */
		*n_args = 6;
		break;
	}
	/* freebsd64___sysctlbyname */
	case 570: {
		struct freebsd64___sysctlbyname_args *p = params;
		uarg[0] = (intptr_t) p->name; /* const char * */
		uarg[1] = p->namelen; /* size_t */
		uarg[2] = (intptr_t) p->old; /* void * */
		uarg[3] = (intptr_t) p->oldlenp; /* size_t * */
		uarg[4] = (intptr_t) p->new; /* void * */
		uarg[5] = p->newlen; /* size_t */
		*n_args = 6;
		break;
	}
	/* freebsd64_shm_open2 */
	case 571: {
		struct freebsd64_shm_open2_args *p = params;
		uarg[0] = (intptr_t) p->path; /* const char * */
		iarg[1] = p->flags; /* int */
		iarg[2] = p->mode; /* mode_t */
		iarg[3] = p->shmflags; /* int */
		uarg[4] = (intptr_t) p->name; /* const char * */
		*n_args = 5;
		break;
	}
	/* freebsd64_shm_rename */
	case 572: {
		struct freebsd64_shm_rename_args *p = params;
		uarg[0] = (intptr_t) p->path_from; /* const char * */
		uarg[1] = (intptr_t) p->path_to; /* const char * */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_sigfastblock */
	case 573: {
		struct freebsd64_sigfastblock_args *p = params;
		iarg[0] = p->cmd; /* int */
		uarg[1] = (intptr_t) p->ptr; /* uint32_t * */
		*n_args = 2;
		break;
	}
	/* freebsd64___realpathat */
	case 574: {
		struct freebsd64___realpathat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		uarg[2] = (intptr_t) p->buf; /* char * */
		uarg[3] = p->size; /* size_t */
		iarg[4] = p->flags; /* int */
		*n_args = 5;
		break;
	}
	/* close_range */
	case 575: {
		struct close_range_args *p = params;
		uarg[0] = p->lowfd; /* u_int */
		uarg[1] = p->highfd; /* u_int */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* freebsd64_rpctls_syscall */
	case 576: {
		struct freebsd64_rpctls_syscall_args *p = params;
		iarg[0] = p->op; /* int */
		uarg[1] = (intptr_t) p->path; /* const char * */
		*n_args = 2;
		break;
	}
	default:
		*n_args = 0;
		break;
	};
}
static void
systrace_entry_setargdesc(int sysnum, int ndx, char *desc, size_t descsz)
{
	const char *p = NULL;
	switch (sysnum) {
	/* nosys */
	case 0:
		break;
	/* sys_exit */
	case 1:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* fork */
	case 2:
		break;
	/* freebsd64_read */
	case 3:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_write */
	case 4:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void *";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_open */
	case 5:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* close */
	case 6:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_wait4 */
	case 7:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland int *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland struct rusage *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_link */
	case 9:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_unlink */
	case 10:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_chdir */
	case 12:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* fchdir */
	case 13:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_chmod */
	case 15:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_chown */
	case 16:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_break */
	case 17:
		switch(ndx) {
		case 0:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* getpid */
	case 20:
		break;
	/* freebsd64_mount */
	case 21:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_unmount */
	case 22:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* setuid */
	case 23:
		switch(ndx) {
		case 0:
			p = "uid_t";
			break;
		default:
			break;
		};
		break;
	/* getuid */
	case 24:
		break;
	/* geteuid */
	case 25:
		break;
	/* freebsd64_ptrace */
	case 26:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "pid_t";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_recvmsg */
	case 27:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct msghdr64 *";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sendmsg */
	case 28:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct msghdr64 *";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_recvfrom */
	case 29:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland struct sockaddr *";
			break;
		case 5:
			p = "userland __socklen_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_accept */
	case 30:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sockaddr *";
			break;
		case 2:
			p = "userland __socklen_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getpeername */
	case 31:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sockaddr *";
			break;
		case 2:
			p = "userland __socklen_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getsockname */
	case 32:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sockaddr *";
			break;
		case 2:
			p = "userland __socklen_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_access */
	case 33:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_chflags */
	case 34:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "u_long";
			break;
		default:
			break;
		};
		break;
	/* fchflags */
	case 35:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "u_long";
			break;
		default:
			break;
		};
		break;
	/* sync */
	case 36:
		break;
	/* kill */
	case 37:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* getppid */
	case 39:
		break;
	/* dup */
	case 41:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* getegid */
	case 43:
		break;
	/* freebsd64_profil */
	case 44:
		switch(ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ktrace */
	case 45:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* getgid */
	case 47:
		break;
	/* freebsd64_getlogin */
	case 49:
		switch(ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setlogin */
	case 50:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_acct */
	case 51:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigaltstack */
	case 53:
		switch(ndx) {
		case 0:
			p = "userland const struct sigaltstack64 *";
			break;
		case 1:
			p = "userland struct sigaltstack64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ioctl */
	case 54:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "u_long";
			break;
		case 2:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* reboot */
	case 55:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_revoke */
	case 56:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_symlink */
	case 57:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_readlink */
	case 58:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_execve */
	case 59:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland char **";
			break;
		case 2:
			p = "userland char **";
			break;
		default:
			break;
		};
		break;
	/* umask */
	case 60:
		switch(ndx) {
		case 0:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_chroot */
	case 61:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_msync */
	case 65:
		switch(ndx) {
		case 0:
			p = "userland void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* vfork */
	case 66:
		break;
	/* sbrk */
	case 69:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* sstk */
	case 70:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_munmap */
	case 73:
		switch(ndx) {
		case 0:
			p = "userland void *";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mprotect */
	case 74:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_madvise */
	case 75:
		switch(ndx) {
		case 0:
			p = "userland void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mincore */
	case 78:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getgroups */
	case 79:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "userland gid_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setgroups */
	case 80:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "userland const gid_t *";
			break;
		default:
			break;
		};
		break;
	/* getpgrp */
	case 81:
		break;
	/* setpgid */
	case 82:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setitimer */
	case 83:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct itimerval *";
			break;
		case 2:
			p = "userland struct itimerval *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_swapon */
	case 85:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getitimer */
	case 86:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct itimerval *";
			break;
		default:
			break;
		};
		break;
	/* getdtablesize */
	case 89:
		break;
	/* dup2 */
	case 90:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fcntl */
	case 92:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "intptr_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_select */
	case 93:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland fd_set *";
			break;
		case 2:
			p = "userland fd_set *";
			break;
		case 3:
			p = "userland fd_set *";
			break;
		case 4:
			p = "userland struct timeval *";
			break;
		default:
			break;
		};
		break;
	/* fsync */
	case 95:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* setpriority */
	case 96:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* socket */
	case 97:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_connect */
	case 98:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct sockaddr *";
			break;
		case 2:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* getpriority */
	case 100:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_bind */
	case 104:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct sockaddr *";
			break;
		case 2:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setsockopt */
	case 105:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const void *";
			break;
		case 4:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* listen */
	case 106:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_gettimeofday */
	case 116:
		switch(ndx) {
		case 0:
			p = "userland struct timeval *";
			break;
		case 1:
			p = "userland struct timezone *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getrusage */
	case 117:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct rusage *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getsockopt */
	case 118:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "userland __socklen_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_readv */
	case 120:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec64 *";
			break;
		case 2:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_writev */
	case 121:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec64 *";
			break;
		case 2:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_settimeofday */
	case 122:
		switch(ndx) {
		case 0:
			p = "userland const struct timeval *";
			break;
		case 1:
			p = "userland const struct timezone *";
			break;
		default:
			break;
		};
		break;
	/* fchown */
	case 123:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* fchmod */
	case 124:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* setreuid */
	case 126:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* setregid */
	case 127:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rename */
	case 128:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* flock */
	case 131:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mkfifo */
	case 132:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sendto */
	case 133:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland const struct sockaddr *";
			break;
		case 5:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* shutdown */
	case 134:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_socketpair */
	case 135:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland int *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mkdir */
	case 136:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rmdir */
	case 137:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_utimes */
	case 138:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const struct timeval *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_adjtime */
	case 140:
		switch(ndx) {
		case 0:
			p = "userland const struct timeval *";
			break;
		case 1:
			p = "userland struct timeval *";
			break;
		default:
			break;
		};
		break;
	/* setsid */
	case 147:
		break;
	/* freebsd64_quotactl */
	case 148:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_nlm_syscall */
	case 154:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland char **";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_nfssvc */
	case 155:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_lgetfh */
	case 160:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland struct fhandle *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getfh */
	case 161:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland struct fhandle *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sysarch */
	case 165:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rtprio */
	case 166:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "pid_t";
			break;
		case 2:
			p = "userland struct rtprio *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_semsys */
	case 169:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "intptr_t";
			break;
		case 2:
			p = "intptr_t";
			break;
		case 3:
			p = "intptr_t";
			break;
		case 4:
			p = "intptr_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_msgsys */
	case 170:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "intptr_t";
			break;
		case 2:
			p = "intptr_t";
			break;
		case 3:
			p = "intptr_t";
			break;
		case 4:
			p = "intptr_t";
			break;
		case 5:
			p = "intptr_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_shmsys */
	case 171:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "intptr_t";
			break;
		case 2:
			p = "intptr_t";
			break;
		case 3:
			p = "intptr_t";
			break;
		default:
			break;
		};
		break;
	/* setfib */
	case 175:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ntp_adjtime */
	case 176:
		switch(ndx) {
		case 0:
			p = "userland struct timex *";
			break;
		default:
			break;
		};
		break;
	/* setgid */
	case 181:
		switch(ndx) {
		case 0:
			p = "gid_t";
			break;
		default:
			break;
		};
		break;
	/* setegid */
	case 182:
		switch(ndx) {
		case 0:
			p = "gid_t";
			break;
		default:
			break;
		};
		break;
	/* seteuid */
	case 183:
		switch(ndx) {
		case 0:
			p = "uid_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_pathconf */
	case 191:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* fpathconf */
	case 192:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getrlimit */
	case 194:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "userland struct rlimit *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setrlimit */
	case 195:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "userland struct rlimit *";
			break;
		default:
			break;
		};
		break;
	/* nosys */
	case 198:
		break;
	/* freebsd64___sysctl */
	case 202:
		switch(ndx) {
		case 0:
			p = "userland int *";
			break;
		case 1:
			p = "u_int";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "userland size_t *";
			break;
		case 4:
			p = "userland const void *";
			break;
		case 5:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mlock */
	case 203:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_munlock */
	case 204:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_undelete */
	case 205:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_futimes */
	case 206:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct timeval *";
			break;
		default:
			break;
		};
		break;
	/* getpgid */
	case 207:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_poll */
	case 209:
		switch(ndx) {
		case 0:
			p = "userland struct pollfd *";
			break;
		case 1:
			p = "u_int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* lkmnosys */
	case 210:
		break;
	/* lkmnosys */
	case 211:
		break;
	/* lkmnosys */
	case 212:
		break;
	/* lkmnosys */
	case 213:
		break;
	/* lkmnosys */
	case 214:
		break;
	/* lkmnosys */
	case 215:
		break;
	/* lkmnosys */
	case 216:
		break;
	/* lkmnosys */
	case 217:
		break;
	/* lkmnosys */
	case 218:
		break;
	/* lkmnosys */
	case 219:
		break;
	/* semget */
	case 221:
		switch(ndx) {
		case 0:
			p = "key_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_semop */
	case 222:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sembuf *";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* msgget */
	case 225:
		switch(ndx) {
		case 0:
			p = "key_t";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_msgsnd */
	case 226:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_msgrcv */
	case 227:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "long";
			break;
		case 4:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_shmat */
	case 228:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void *";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_shmdt */
	case 230:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		default:
			break;
		};
		break;
	/* shmget */
	case 231:
		switch(ndx) {
		case 0:
			p = "key_t";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_clock_gettime */
	case 232:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_clock_settime */
	case 233:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_clock_getres */
	case 234:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ktimer_create */
	case 235:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct sigevent64 *";
			break;
		case 2:
			p = "userland int *";
			break;
		default:
			break;
		};
		break;
	/* ktimer_delete */
	case 236:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ktimer_settime */
	case 237:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct itimerspec *";
			break;
		case 3:
			p = "userland struct itimerspec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ktimer_gettime */
	case 238:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct itimerspec *";
			break;
		default:
			break;
		};
		break;
	/* ktimer_getoverrun */
	case 239:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_nanosleep */
	case 240:
		switch(ndx) {
		case 0:
			p = "userland const struct timespec *";
			break;
		case 1:
			p = "userland struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ffclock_getcounter */
	case 241:
		switch(ndx) {
		case 0:
			p = "userland ffcounter *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ffclock_setestimate */
	case 242:
		switch(ndx) {
		case 0:
			p = "userland struct ffclock_estimate *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ffclock_getestimate */
	case 243:
		switch(ndx) {
		case 0:
			p = "userland struct ffclock_estimate *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_clock_nanosleep */
	case 244:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct timespec *";
			break;
		case 3:
			p = "userland struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_clock_getcpuclockid2 */
	case 247:
		switch(ndx) {
		case 0:
			p = "id_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland clockid_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ntp_gettime */
	case 248:
		switch(ndx) {
		case 0:
			p = "userland struct ntptimeval *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_minherit */
	case 250:
		switch(ndx) {
		case 0:
			p = "userland void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* rfork */
	case 251:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* issetugid */
	case 253:
		break;
	/* freebsd64_lchown */
	case 254:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_read */
	case 255:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_write */
	case 256:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_lio_listio */
	case 257:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct aiocb64 * const *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland struct sigevent64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kbounce */
	case 258:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_flag_captured */
	case 259:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_lchmod */
	case 274:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_lutimes */
	case 276:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const struct timeval *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_preadv */
	case 289:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec64 *";
			break;
		case 2:
			p = "u_int";
			break;
		case 3:
			p = "off_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_pwritev */
	case 290:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec64 *";
			break;
		case 2:
			p = "u_int";
			break;
		case 3:
			p = "off_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fhopen */
	case 298:
		switch(ndx) {
		case 0:
			p = "userland const struct fhandle *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* modnext */
	case 300:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_modstat */
	case 301:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct module_stat *";
			break;
		default:
			break;
		};
		break;
	/* modfnext */
	case 302:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_modfind */
	case 303:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kldload */
	case 304:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* kldunload */
	case 305:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kldfind */
	case 306:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* kldnext */
	case 307:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kldstat */
	case 308:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct kld_file_stat64 *";
			break;
		default:
			break;
		};
		break;
	/* kldfirstmod */
	case 309:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* getsid */
	case 310:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		default:
			break;
		};
		break;
	/* setresuid */
	case 311:
		switch(ndx) {
		case 0:
			p = "uid_t";
			break;
		case 1:
			p = "uid_t";
			break;
		case 2:
			p = "uid_t";
			break;
		default:
			break;
		};
		break;
	/* setresgid */
	case 312:
		switch(ndx) {
		case 0:
			p = "gid_t";
			break;
		case 1:
			p = "gid_t";
			break;
		case 2:
			p = "gid_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_return */
	case 314:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_suspend */
	case 315:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb64 * const *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_cancel */
	case 316:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct aiocb64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_error */
	case 317:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb64 *";
			break;
		default:
			break;
		};
		break;
	/* yield */
	case 321:
		break;
	/* mlockall */
	case 324:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* munlockall */
	case 325:
		break;
	/* freebsd64___getcwd */
	case 326:
		switch(ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sched_setparam */
	case 327:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "userland const struct sched_param *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sched_getparam */
	case 328:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "userland struct sched_param *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sched_setscheduler */
	case 329:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct sched_param *";
			break;
		default:
			break;
		};
		break;
	/* sched_getscheduler */
	case 330:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		default:
			break;
		};
		break;
	/* sched_yield */
	case 331:
		break;
	/* sched_get_priority_max */
	case 332:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* sched_get_priority_min */
	case 333:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sched_rr_get_interval */
	case 334:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "userland struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_utrace */
	case 335:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kldsym */
	case 337:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_jail */
	case 338:
		switch(ndx) {
		case 0:
			p = "userland struct jail64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_nnpfs_syscall */
	case 339:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigprocmask */
	case 340:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const sigset_t *";
			break;
		case 2:
			p = "userland sigset_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigsuspend */
	case 341:
		switch(ndx) {
		case 0:
			p = "userland const sigset_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigpending */
	case 343:
		switch(ndx) {
		case 0:
			p = "userland sigset_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigtimedwait */
	case 345:
		switch(ndx) {
		case 0:
			p = "userland const sigset_t *";
			break;
		case 1:
			p = "userland struct siginfo64 *";
			break;
		case 2:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigwaitinfo */
	case 346:
		switch(ndx) {
		case 0:
			p = "userland const sigset_t *";
			break;
		case 1:
			p = "userland struct siginfo64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_get_file */
	case 347:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_set_file */
	case 348:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_get_fd */
	case 349:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_set_fd */
	case 350:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_delete_file */
	case 351:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "acl_type_t";
			break;
		default:
			break;
		};
		break;
	/* __acl_delete_fd */
	case 352:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "acl_type_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_aclcheck_file */
	case 353:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_aclcheck_fd */
	case 354:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattrctl */
	case 355:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_set_file */
	case 356:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_get_file */
	case 357:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_delete_file */
	case 358:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_waitcomplete */
	case 359:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb64 **";
			break;
		case 1:
			p = "userland struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getresuid */
	case 360:
		switch(ndx) {
		case 0:
			p = "userland uid_t *";
			break;
		case 1:
			p = "userland uid_t *";
			break;
		case 2:
			p = "userland uid_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getresgid */
	case 361:
		switch(ndx) {
		case 0:
			p = "userland gid_t *";
			break;
		case 1:
			p = "userland gid_t *";
			break;
		case 2:
			p = "userland gid_t *";
			break;
		default:
			break;
		};
		break;
	/* kqueue */
	case 362:
		break;
	/* freebsd64_extattr_set_fd */
	case 371:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_get_fd */
	case 372:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_delete_fd */
	case 373:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* __setugid */
	case 374:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_eaccess */
	case 376:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* afs3_syscall */
	case 377:
		switch(ndx) {
		case 0:
			p = "long";
			break;
		case 1:
			p = "long";
			break;
		case 2:
			p = "long";
			break;
		case 3:
			p = "long";
			break;
		case 4:
			p = "long";
			break;
		case 5:
			p = "long";
			break;
		case 6:
			p = "long";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_nmount */
	case 378:
		switch(ndx) {
		case 0:
			p = "userland struct iovec64 *";
			break;
		case 1:
			p = "unsigned int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_get_proc */
	case 384:
		switch(ndx) {
		case 0:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_set_proc */
	case 385:
		switch(ndx) {
		case 0:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_get_fd */
	case 386:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_get_file */
	case 387:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_set_fd */
	case 388:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_set_file */
	case 389:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kenv */
	case 390:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_lchflags */
	case 391:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "u_long";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_uuidgen */
	case 392:
		switch(ndx) {
		case 0:
			p = "userland struct uuid *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sendfile */
	case 393:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "off_t";
			break;
		case 3:
			p = "size_t";
			break;
		case 4:
			p = "userland struct sf_hdtr64 *";
			break;
		case 5:
			p = "userland off_t *";
			break;
		case 6:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mac_syscall */
	case 394:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* ksem_close */
	case 400:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		default:
			break;
		};
		break;
	/* ksem_post */
	case 401:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		default:
			break;
		};
		break;
	/* ksem_wait */
	case 402:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		default:
			break;
		};
		break;
	/* ksem_trywait */
	case 403:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ksem_init */
	case 404:
		switch(ndx) {
		case 0:
			p = "userland semid_t *";
			break;
		case 1:
			p = "unsigned int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ksem_open */
	case 405:
		switch(ndx) {
		case 0:
			p = "userland semid_t *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "mode_t";
			break;
		case 4:
			p = "unsigned int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ksem_unlink */
	case 406:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ksem_getvalue */
	case 407:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		case 1:
			p = "userland int *";
			break;
		default:
			break;
		};
		break;
	/* ksem_destroy */
	case 408:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_get_pid */
	case 409:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_get_link */
	case 410:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_set_link */
	case 411:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_set_link */
	case 412:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_get_link */
	case 413:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_delete_link */
	case 414:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___mac_execve */
	case 415:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland char **";
			break;
		case 2:
			p = "userland char **";
			break;
		case 3:
			p = "userland struct mac64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigaction */
	case 416:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct sigaction64 *";
			break;
		case 2:
			p = "userland struct sigaction64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigreturn */
	case 417:
		switch(ndx) {
		case 0:
			p = "userland const struct __ucontext64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getcontext */
	case 421:
		switch(ndx) {
		case 0:
			p = "userland struct __ucontext64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setcontext */
	case 422:
		switch(ndx) {
		case 0:
			p = "userland const struct __ucontext64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_swapcontext */
	case 423:
		switch(ndx) {
		case 0:
			p = "userland struct __ucontext64 *";
			break;
		case 1:
			p = "userland const struct __ucontext64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_swapoff */
	case 424:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_get_link */
	case 425:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_set_link */
	case 426:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_delete_link */
	case 427:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "acl_type_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___acl_aclcheck_link */
	case 428:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigwait */
	case 429:
		switch(ndx) {
		case 0:
			p = "userland const sigset_t *";
			break;
		case 1:
			p = "userland int *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_thr_create */
	case 430:
		switch(ndx) {
		case 0:
			p = "userland struct __ucontext64 *";
			break;
		case 1:
			p = "userland long *";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_thr_exit */
	case 431:
		switch(ndx) {
		case 0:
			p = "userland long *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_thr_self */
	case 432:
		switch(ndx) {
		case 0:
			p = "userland long *";
			break;
		default:
			break;
		};
		break;
	/* thr_kill */
	case 433:
		switch(ndx) {
		case 0:
			p = "long";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* jail_attach */
	case 436:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_list_fd */
	case 437:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_list_file */
	case 438:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_extattr_list_link */
	case 439:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ksem_timedwait */
	case 441:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		case 1:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_thr_suspend */
	case 442:
		switch(ndx) {
		case 0:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* thr_wake */
	case 443:
		switch(ndx) {
		case 0:
			p = "long";
			break;
		default:
			break;
		};
		break;
	/* kldunloadf */
	case 444:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_audit */
	case 445:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_auditon */
	case 446:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getauid */
	case 447:
		switch(ndx) {
		case 0:
			p = "userland uid_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setauid */
	case 448:
		switch(ndx) {
		case 0:
			p = "userland uid_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getaudit */
	case 449:
		switch(ndx) {
		case 0:
			p = "userland struct auditinfo *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setaudit */
	case 450:
		switch(ndx) {
		case 0:
			p = "userland struct auditinfo *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getaudit_addr */
	case 451:
		switch(ndx) {
		case 0:
			p = "userland struct auditinfo_addr *";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setaudit_addr */
	case 452:
		switch(ndx) {
		case 0:
			p = "userland struct auditinfo_addr *";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_auditctl */
	case 453:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64__umtx_op */
	case 454:
		switch(ndx) {
		case 0:
			p = "userland void *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "u_long";
			break;
		case 3:
			p = "userland void *";
			break;
		case 4:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_thr_new */
	case 455:
		switch(ndx) {
		case 0:
			p = "userland struct thr_param64 *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigqueue */
	case 456:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kmq_open */
	case 457:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "mode_t";
			break;
		case 3:
			p = "userland const struct mq_attr *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kmq_setattr */
	case 458:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct mq_attr *";
			break;
		case 2:
			p = "userland struct mq_attr *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kmq_timedreceive */
	case 459:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "userland unsigned *";
			break;
		case 4:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kmq_timedsend */
	case 460:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "unsigned";
			break;
		case 4:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kmq_notify */
	case 461:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct sigevent64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kmq_unlink */
	case 462:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_abort2 */
	case 463:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void **";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_thr_set_name */
	case 464:
		switch(ndx) {
		case 0:
			p = "long";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_fsync */
	case 465:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct aiocb64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rtprio_thread */
	case 466:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "lwpid_t";
			break;
		case 2:
			p = "userland struct rtprio *";
			break;
		default:
			break;
		};
		break;
	/* sctp_peeloff */
	case 471:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "uint32_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sctp_generic_sendmsg */
	case 472:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const struct sockaddr *";
			break;
		case 4:
			p = "__socklen_t";
			break;
		case 5:
			p = "userland struct sctp_sndrcvinfo *";
			break;
		case 6:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sctp_generic_sendmsg_iov */
	case 473:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec64 *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const struct sockaddr *";
			break;
		case 4:
			p = "__socklen_t";
			break;
		case 5:
			p = "userland struct sctp_sndrcvinfo *";
			break;
		case 6:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sctp_generic_recvmsg */
	case 474:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec64 *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland struct sockaddr *";
			break;
		case 4:
			p = "userland __socklen_t *";
			break;
		case 5:
			p = "userland struct sctp_sndrcvinfo *";
			break;
		case 6:
			p = "userland int *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_pread */
	case 475:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "off_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_pwrite */
	case 476:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "off_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mmap */
	case 477:
		switch(ndx) {
		case 0:
			p = "userland void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "int";
			break;
		case 5:
			p = "off_t";
			break;
		default:
			break;
		};
		break;
	/* lseek */
	case 478:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "off_t";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_truncate */
	case 479:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "off_t";
			break;
		default:
			break;
		};
		break;
	/* ftruncate */
	case 480:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "off_t";
			break;
		default:
			break;
		};
		break;
	/* thr_kill2 */
	case 481:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "long";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_shm_unlink */
	case 483:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cpuset */
	case 484:
		switch(ndx) {
		case 0:
			p = "userland cpusetid_t *";
			break;
		default:
			break;
		};
		break;
	/* cpuset_setid */
	case 485:
		switch(ndx) {
		case 0:
			p = "cpuwhich_t";
			break;
		case 1:
			p = "id_t";
			break;
		case 2:
			p = "cpusetid_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cpuset_getid */
	case 486:
		switch(ndx) {
		case 0:
			p = "cpulevel_t";
			break;
		case 1:
			p = "cpuwhich_t";
			break;
		case 2:
			p = "id_t";
			break;
		case 3:
			p = "userland cpusetid_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cpuset_getaffinity */
	case 487:
		switch(ndx) {
		case 0:
			p = "cpulevel_t";
			break;
		case 1:
			p = "cpuwhich_t";
			break;
		case 2:
			p = "id_t";
			break;
		case 3:
			p = "size_t";
			break;
		case 4:
			p = "userland cpuset_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cpuset_setaffinity */
	case 488:
		switch(ndx) {
		case 0:
			p = "cpulevel_t";
			break;
		case 1:
			p = "cpuwhich_t";
			break;
		case 2:
			p = "id_t";
			break;
		case 3:
			p = "size_t";
			break;
		case 4:
			p = "userland const cpuset_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_faccessat */
	case 489:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fchmodat */
	case 490:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "mode_t";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fchownat */
	case 491:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "uid_t";
			break;
		case 3:
			p = "gid_t";
			break;
		case 4:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fexecve */
	case 492:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char **";
			break;
		case 2:
			p = "userland char **";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_futimesat */
	case 494:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland const struct timeval *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_linkat */
	case 495:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const char *";
			break;
		case 4:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mkdirat */
	case 496:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mkfifoat */
	case 497:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_openat */
	case 499:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_readlinkat */
	case 500:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_renameat */
	case 501:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_symlinkat */
	case 502:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_unlinkat */
	case 503:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* posix_openpt */
	case 504:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_gssd_syscall */
	case 505:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_jail_get */
	case 506:
		switch(ndx) {
		case 0:
			p = "userland struct iovec64 *";
			break;
		case 1:
			p = "unsigned int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_jail_set */
	case 507:
		switch(ndx) {
		case 0:
			p = "userland struct iovec64 *";
			break;
		case 1:
			p = "unsigned int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* jail_remove */
	case 508:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___semctl */
	case 510:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland union semun64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_msgctl */
	case 511:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland struct msqid_ds64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_shmctl */
	case 512:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland struct shmid_ds *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_lpathconf */
	case 513:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___cap_rights_get */
	case 515:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland cap_rights_t *";
			break;
		default:
			break;
		};
		break;
	/* cap_enter */
	case 516:
		break;
	/* freebsd64_cap_getmode */
	case 517:
		switch(ndx) {
		case 0:
			p = "userland u_int *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_pdfork */
	case 518:
		switch(ndx) {
		case 0:
			p = "userland int *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* pdkill */
	case 519:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_pdgetpid */
	case 520:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland pid_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_pselect */
	case 522:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland fd_set *";
			break;
		case 2:
			p = "userland fd_set *";
			break;
		case 3:
			p = "userland fd_set *";
			break;
		case 4:
			p = "userland const struct timespec *";
			break;
		case 5:
			p = "userland const sigset_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getloginclass */
	case 523:
		switch(ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_setloginclass */
	case 524:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rctl_get_racct */
	case 525:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rctl_get_rules */
	case 526:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rctl_get_limits */
	case 527:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rctl_add_rule */
	case 528:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rctl_remove_rule */
	case 529:
		switch(ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* posix_fallocate */
	case 530:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "off_t";
			break;
		case 2:
			p = "off_t";
			break;
		default:
			break;
		};
		break;
	/* posix_fadvise */
	case 531:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "off_t";
			break;
		case 2:
			p = "off_t";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_wait6 */
	case 532:
		switch(ndx) {
		case 0:
			p = "idtype_t";
			break;
		case 1:
			p = "id_t";
			break;
		case 2:
			p = "userland int *";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland struct __wrusage *";
			break;
		case 5:
			p = "userland struct siginfo64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cap_rights_limit */
	case 533:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland cap_rights_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cap_ioctls_limit */
	case 534:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const u_long *";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cap_ioctls_get */
	case 535:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland u_long *";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cap_fcntls_limit */
	case 536:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "uint32_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cap_fcntls_get */
	case 537:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland uint32_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_bindat */
	case 538:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct sockaddr *";
			break;
		case 3:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_connectat */
	case 539:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct sockaddr *";
			break;
		case 3:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_chflagsat */
	case 540:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "u_long";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_accept4 */
	case 541:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sockaddr *";
			break;
		case 2:
			p = "userland __socklen_t *";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_pipe2 */
	case 542:
		switch(ndx) {
		case 0:
			p = "userland int *";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_aio_mlock */
	case 543:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb64 *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_procctl */
	case 544:
		switch(ndx) {
		case 0:
			p = "idtype_t";
			break;
		case 1:
			p = "id_t";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_ppoll */
	case 545:
		switch(ndx) {
		case 0:
			p = "userland struct pollfd *";
			break;
		case 1:
			p = "u_int";
			break;
		case 2:
			p = "userland const struct timespec *";
			break;
		case 3:
			p = "userland const sigset_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_futimens */
	case 546:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_utimensat */
	case 547:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland const struct timespec *";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* fdatasync */
	case 550:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fstat */
	case 551:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct stat *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fstatat */
	case 552:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland struct stat *";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fhstat */
	case 553:
		switch(ndx) {
		case 0:
			p = "userland const struct fhandle *";
			break;
		case 1:
			p = "userland struct stat *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getdirentries */
	case 554:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "userland off_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_statfs */
	case 555:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland struct statfs *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fstatfs */
	case 556:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct statfs *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getfsstat */
	case 557:
		switch(ndx) {
		case 0:
			p = "userland struct statfs *";
			break;
		case 1:
			p = "long";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fhstatfs */
	case 558:
		switch(ndx) {
		case 0:
			p = "userland const struct fhandle *";
			break;
		case 1:
			p = "userland struct statfs *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_mknodat */
	case 559:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "mode_t";
			break;
		case 3:
			p = "dev_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_kevent */
	case 560:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct kevent64 *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland struct kevent64 *";
			break;
		case 4:
			p = "int";
			break;
		case 5:
			p = "userland const struct timespec *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cpuset_getdomain */
	case 561:
		switch(ndx) {
		case 0:
			p = "cpulevel_t";
			break;
		case 1:
			p = "cpuwhich_t";
			break;
		case 2:
			p = "id_t";
			break;
		case 3:
			p = "size_t";
			break;
		case 4:
			p = "userland domainset_t *";
			break;
		case 5:
			p = "userland int *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_cpuset_setdomain */
	case 562:
		switch(ndx) {
		case 0:
			p = "cpulevel_t";
			break;
		case 1:
			p = "cpuwhich_t";
			break;
		case 2:
			p = "id_t";
			break;
		case 3:
			p = "size_t";
			break;
		case 4:
			p = "userland domainset_t *";
			break;
		case 5:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getrandom */
	case 563:
		switch(ndx) {
		case 0:
			p = "userland void *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "unsigned int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_getfhat */
	case 564:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "userland struct fhandle *";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fhlink */
	case 565:
		switch(ndx) {
		case 0:
			p = "userland struct fhandle *";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fhlinkat */
	case 566:
		switch(ndx) {
		case 0:
			p = "userland struct fhandle *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_fhreadlink */
	case 567:
		switch(ndx) {
		case 0:
			p = "userland struct fhandle *";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_funlinkat */
	case 568:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_copy_file_range */
	case 569:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland off_t *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland off_t *";
			break;
		case 4:
			p = "size_t";
			break;
		case 5:
			p = "unsigned int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___sysctlbyname */
	case 570:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void *";
			break;
		case 3:
			p = "userland size_t *";
			break;
		case 4:
			p = "userland void *";
			break;
		case 5:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_shm_open2 */
	case 571:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "mode_t";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_shm_rename */
	case 572:
		switch(ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_sigfastblock */
	case 573:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland uint32_t *";
			break;
		default:
			break;
		};
		break;
	/* freebsd64___realpathat */
	case 574:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "size_t";
			break;
		case 4:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* close_range */
	case 575:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "u_int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* freebsd64_rpctls_syscall */
	case 576:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	default:
		break;
	};
	if (p != NULL)
		strlcpy(desc, p, descsz);
}
static void
systrace_return_setargdesc(int sysnum, int ndx, char *desc, size_t descsz)
{
	const char *p = NULL;
	switch (sysnum) {
	/* nosys */
	case 0:
	/* sys_exit */
	case 1:
		if (ndx == 0 || ndx == 1)
			p = "void";
		break;
	/* fork */
	case 2:
	/* freebsd64_read */
	case 3:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_write */
	case 4:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_open */
	case 5:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* close */
	case 6:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_wait4 */
	case 7:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_link */
	case 9:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_unlink */
	case 10:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_chdir */
	case 12:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fchdir */
	case 13:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_chmod */
	case 15:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_chown */
	case 16:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_break */
	case 17:
		if (ndx == 0 || ndx == 1)
			p = "void *";
		break;
	/* getpid */
	case 20:
	/* freebsd64_mount */
	case 21:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_unmount */
	case 22:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setuid */
	case 23:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getuid */
	case 24:
	/* geteuid */
	case 25:
	/* freebsd64_ptrace */
	case 26:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_recvmsg */
	case 27:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_sendmsg */
	case 28:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_recvfrom */
	case 29:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_accept */
	case 30:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getpeername */
	case 31:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getsockname */
	case 32:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_access */
	case 33:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_chflags */
	case 34:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fchflags */
	case 35:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sync */
	case 36:
	/* kill */
	case 37:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getppid */
	case 39:
	/* dup */
	case 41:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getegid */
	case 43:
	/* freebsd64_profil */
	case 44:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ktrace */
	case 45:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getgid */
	case 47:
	/* freebsd64_getlogin */
	case 49:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setlogin */
	case 50:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_acct */
	case 51:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigaltstack */
	case 53:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ioctl */
	case 54:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* reboot */
	case 55:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_revoke */
	case 56:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_symlink */
	case 57:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_readlink */
	case 58:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_execve */
	case 59:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* umask */
	case 60:
		if (ndx == 0 || ndx == 1)
			p = "mode_t";
		break;
	/* freebsd64_chroot */
	case 61:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_msync */
	case 65:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* vfork */
	case 66:
	/* sbrk */
	case 69:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sstk */
	case 70:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_munmap */
	case 73:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mprotect */
	case 74:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_madvise */
	case 75:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mincore */
	case 78:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getgroups */
	case 79:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setgroups */
	case 80:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getpgrp */
	case 81:
	/* setpgid */
	case 82:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setitimer */
	case 83:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_swapon */
	case 85:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getitimer */
	case 86:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getdtablesize */
	case 89:
	/* dup2 */
	case 90:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fcntl */
	case 92:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_select */
	case 93:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fsync */
	case 95:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setpriority */
	case 96:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* socket */
	case 97:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_connect */
	case 98:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getpriority */
	case 100:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_bind */
	case 104:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setsockopt */
	case 105:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* listen */
	case 106:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_gettimeofday */
	case 116:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getrusage */
	case 117:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getsockopt */
	case 118:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_readv */
	case 120:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_writev */
	case 121:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_settimeofday */
	case 122:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fchown */
	case 123:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fchmod */
	case 124:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setreuid */
	case 126:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setregid */
	case 127:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rename */
	case 128:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* flock */
	case 131:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mkfifo */
	case 132:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sendto */
	case 133:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* shutdown */
	case 134:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_socketpair */
	case 135:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mkdir */
	case 136:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rmdir */
	case 137:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_utimes */
	case 138:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_adjtime */
	case 140:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setsid */
	case 147:
	/* freebsd64_quotactl */
	case 148:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_nlm_syscall */
	case 154:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_nfssvc */
	case 155:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_lgetfh */
	case 160:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getfh */
	case 161:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sysarch */
	case 165:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rtprio */
	case 166:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_semsys */
	case 169:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_msgsys */
	case 170:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_shmsys */
	case 171:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setfib */
	case 175:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ntp_adjtime */
	case 176:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setgid */
	case 181:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setegid */
	case 182:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* seteuid */
	case 183:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_pathconf */
	case 191:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fpathconf */
	case 192:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getrlimit */
	case 194:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setrlimit */
	case 195:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* nosys */
	case 198:
	/* freebsd64___sysctl */
	case 202:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mlock */
	case 203:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_munlock */
	case 204:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_undelete */
	case 205:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_futimes */
	case 206:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getpgid */
	case 207:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_poll */
	case 209:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* lkmnosys */
	case 210:
	/* lkmnosys */
	case 211:
	/* lkmnosys */
	case 212:
	/* lkmnosys */
	case 213:
	/* lkmnosys */
	case 214:
	/* lkmnosys */
	case 215:
	/* lkmnosys */
	case 216:
	/* lkmnosys */
	case 217:
	/* lkmnosys */
	case 218:
	/* lkmnosys */
	case 219:
	/* semget */
	case 221:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_semop */
	case 222:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* msgget */
	case 225:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_msgsnd */
	case 226:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_msgrcv */
	case 227:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_shmat */
	case 228:
		if (ndx == 0 || ndx == 1)
			p = "void *";
		break;
	/* freebsd64_shmdt */
	case 230:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* shmget */
	case 231:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_clock_gettime */
	case 232:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_clock_settime */
	case 233:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_clock_getres */
	case 234:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ktimer_create */
	case 235:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ktimer_delete */
	case 236:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ktimer_settime */
	case 237:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ktimer_gettime */
	case 238:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ktimer_getoverrun */
	case 239:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_nanosleep */
	case 240:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ffclock_getcounter */
	case 241:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ffclock_setestimate */
	case 242:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ffclock_getestimate */
	case 243:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_clock_nanosleep */
	case 244:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_clock_getcpuclockid2 */
	case 247:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ntp_gettime */
	case 248:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_minherit */
	case 250:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* rfork */
	case 251:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* issetugid */
	case 253:
	/* freebsd64_lchown */
	case 254:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_aio_read */
	case 255:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_aio_write */
	case 256:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_lio_listio */
	case 257:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kbounce */
	case 258:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_flag_captured */
	case 259:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_lchmod */
	case 274:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_lutimes */
	case 276:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_preadv */
	case 289:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_pwritev */
	case 290:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_fhopen */
	case 298:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* modnext */
	case 300:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_modstat */
	case 301:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* modfnext */
	case 302:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_modfind */
	case 303:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kldload */
	case 304:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* kldunload */
	case 305:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kldfind */
	case 306:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* kldnext */
	case 307:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kldstat */
	case 308:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* kldfirstmod */
	case 309:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getsid */
	case 310:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setresuid */
	case 311:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setresgid */
	case 312:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_aio_return */
	case 314:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_aio_suspend */
	case 315:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_aio_cancel */
	case 316:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_aio_error */
	case 317:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* yield */
	case 321:
	/* mlockall */
	case 324:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* munlockall */
	case 325:
	/* freebsd64___getcwd */
	case 326:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sched_setparam */
	case 327:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sched_getparam */
	case 328:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sched_setscheduler */
	case 329:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sched_getscheduler */
	case 330:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sched_yield */
	case 331:
	/* sched_get_priority_max */
	case 332:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sched_get_priority_min */
	case 333:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sched_rr_get_interval */
	case 334:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_utrace */
	case 335:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kldsym */
	case 337:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_jail */
	case 338:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_nnpfs_syscall */
	case 339:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigprocmask */
	case 340:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigsuspend */
	case 341:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigpending */
	case 343:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigtimedwait */
	case 345:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigwaitinfo */
	case 346:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_get_file */
	case 347:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_set_file */
	case 348:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_get_fd */
	case 349:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_set_fd */
	case 350:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_delete_file */
	case 351:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* __acl_delete_fd */
	case 352:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_aclcheck_file */
	case 353:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_aclcheck_fd */
	case 354:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_extattrctl */
	case 355:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_extattr_set_file */
	case 356:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_extattr_get_file */
	case 357:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_extattr_delete_file */
	case 358:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_aio_waitcomplete */
	case 359:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_getresuid */
	case 360:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getresgid */
	case 361:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* kqueue */
	case 362:
	/* freebsd64_extattr_set_fd */
	case 371:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_extattr_get_fd */
	case 372:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_extattr_delete_fd */
	case 373:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* __setugid */
	case 374:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_eaccess */
	case 376:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* afs3_syscall */
	case 377:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_nmount */
	case 378:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_get_proc */
	case 384:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_set_proc */
	case 385:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_get_fd */
	case 386:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_get_file */
	case 387:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_set_fd */
	case 388:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_set_file */
	case 389:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kenv */
	case 390:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_lchflags */
	case 391:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_uuidgen */
	case 392:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sendfile */
	case 393:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mac_syscall */
	case 394:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ksem_close */
	case 400:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ksem_post */
	case 401:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ksem_wait */
	case 402:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ksem_trywait */
	case 403:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ksem_init */
	case 404:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ksem_open */
	case 405:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ksem_unlink */
	case 406:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ksem_getvalue */
	case 407:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ksem_destroy */
	case 408:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_get_pid */
	case 409:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_get_link */
	case 410:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_set_link */
	case 411:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_extattr_set_link */
	case 412:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_extattr_get_link */
	case 413:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_extattr_delete_link */
	case 414:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___mac_execve */
	case 415:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigaction */
	case 416:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigreturn */
	case 417:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getcontext */
	case 421:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setcontext */
	case 422:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_swapcontext */
	case 423:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_swapoff */
	case 424:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_get_link */
	case 425:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_set_link */
	case 426:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_delete_link */
	case 427:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___acl_aclcheck_link */
	case 428:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigwait */
	case 429:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_thr_create */
	case 430:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_thr_exit */
	case 431:
		if (ndx == 0 || ndx == 1)
			p = "void";
		break;
	/* freebsd64_thr_self */
	case 432:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* thr_kill */
	case 433:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* jail_attach */
	case 436:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_extattr_list_fd */
	case 437:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_extattr_list_file */
	case 438:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_extattr_list_link */
	case 439:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_ksem_timedwait */
	case 441:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_thr_suspend */
	case 442:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* thr_wake */
	case 443:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* kldunloadf */
	case 444:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_audit */
	case 445:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_auditon */
	case 446:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getauid */
	case 447:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setauid */
	case 448:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getaudit */
	case 449:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setaudit */
	case 450:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getaudit_addr */
	case 451:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setaudit_addr */
	case 452:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_auditctl */
	case 453:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64__umtx_op */
	case 454:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_thr_new */
	case 455:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigqueue */
	case 456:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kmq_open */
	case 457:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kmq_setattr */
	case 458:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kmq_timedreceive */
	case 459:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kmq_timedsend */
	case 460:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kmq_notify */
	case 461:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kmq_unlink */
	case 462:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_abort2 */
	case 463:
		if (ndx == 0 || ndx == 1)
			p = "void";
		break;
	/* freebsd64_thr_set_name */
	case 464:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_aio_fsync */
	case 465:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rtprio_thread */
	case 466:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sctp_peeloff */
	case 471:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sctp_generic_sendmsg */
	case 472:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sctp_generic_sendmsg_iov */
	case 473:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sctp_generic_recvmsg */
	case 474:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_pread */
	case 475:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_pwrite */
	case 476:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_mmap */
	case 477:
		if (ndx == 0 || ndx == 1)
			p = "void *";
		break;
	/* lseek */
	case 478:
		if (ndx == 0 || ndx == 1)
			p = "off_t";
		break;
	/* freebsd64_truncate */
	case 479:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ftruncate */
	case 480:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* thr_kill2 */
	case 481:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_shm_unlink */
	case 483:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cpuset */
	case 484:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cpuset_setid */
	case 485:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cpuset_getid */
	case 486:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cpuset_getaffinity */
	case 487:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cpuset_setaffinity */
	case 488:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_faccessat */
	case 489:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fchmodat */
	case 490:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fchownat */
	case 491:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fexecve */
	case 492:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_futimesat */
	case 494:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_linkat */
	case 495:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mkdirat */
	case 496:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mkfifoat */
	case 497:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_openat */
	case 499:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_readlinkat */
	case 500:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_renameat */
	case 501:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_symlinkat */
	case 502:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_unlinkat */
	case 503:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* posix_openpt */
	case 504:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_gssd_syscall */
	case 505:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_jail_get */
	case 506:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_jail_set */
	case 507:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* jail_remove */
	case 508:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___semctl */
	case 510:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_msgctl */
	case 511:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_shmctl */
	case 512:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_lpathconf */
	case 513:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___cap_rights_get */
	case 515:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cap_enter */
	case 516:
	/* freebsd64_cap_getmode */
	case 517:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_pdfork */
	case 518:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* pdkill */
	case 519:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_pdgetpid */
	case 520:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_pselect */
	case 522:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getloginclass */
	case 523:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_setloginclass */
	case 524:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rctl_get_racct */
	case 525:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rctl_get_rules */
	case 526:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rctl_get_limits */
	case 527:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rctl_add_rule */
	case 528:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rctl_remove_rule */
	case 529:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* posix_fallocate */
	case 530:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* posix_fadvise */
	case 531:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_wait6 */
	case 532:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cap_rights_limit */
	case 533:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cap_ioctls_limit */
	case 534:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cap_ioctls_get */
	case 535:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cap_fcntls_limit */
	case 536:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cap_fcntls_get */
	case 537:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_bindat */
	case 538:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_connectat */
	case 539:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_chflagsat */
	case 540:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_accept4 */
	case 541:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_pipe2 */
	case 542:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_aio_mlock */
	case 543:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_procctl */
	case 544:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_ppoll */
	case 545:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_futimens */
	case 546:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_utimensat */
	case 547:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fdatasync */
	case 550:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fstat */
	case 551:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fstatat */
	case 552:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fhstat */
	case 553:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getdirentries */
	case 554:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64_statfs */
	case 555:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fstatfs */
	case 556:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getfsstat */
	case 557:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fhstatfs */
	case 558:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_mknodat */
	case 559:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_kevent */
	case 560:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cpuset_getdomain */
	case 561:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_cpuset_setdomain */
	case 562:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getrandom */
	case 563:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_getfhat */
	case 564:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fhlink */
	case 565:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fhlinkat */
	case 566:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_fhreadlink */
	case 567:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_funlinkat */
	case 568:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_copy_file_range */
	case 569:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* freebsd64___sysctlbyname */
	case 570:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_shm_open2 */
	case 571:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_shm_rename */
	case 572:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_sigfastblock */
	case 573:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64___realpathat */
	case 574:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* close_range */
	case 575:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* freebsd64_rpctls_syscall */
	case 576:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	default:
		break;
	};
	if (p != NULL)
		strlcpy(desc, p, descsz);
}
