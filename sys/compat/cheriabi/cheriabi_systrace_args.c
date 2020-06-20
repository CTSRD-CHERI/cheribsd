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
	/* cheriabi_read */
	case 3: {
		struct cheriabi_read_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* void * __capability */
		uarg[2] = p->nbyte; /* size_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_write */
	case 4: {
		struct cheriabi_write_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* const void * __capability */
		uarg[2] = p->nbyte; /* size_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_open */
	case 5: {
		struct cheriabi_open_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_wait4 */
	case 7: {
		struct cheriabi_wait4_args *p = params;
		iarg[0] = p->pid; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->status; /* int * __capability */
		iarg[2] = p->options; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->rusage; /* struct rusage * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_link */
	case 9: {
		struct cheriabi_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->to; /* const char * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_unlink */
	case 10: {
		struct cheriabi_unlink_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_chdir */
	case 12: {
		struct cheriabi_chdir_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_chmod */
	case 15: {
		struct cheriabi_chmod_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_chown */
	case 16: {
		struct cheriabi_chown_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->uid; /* int */
		iarg[2] = p->gid; /* int */
		*n_args = 3;
		break;
	}
	/* getpid */
	case 20: {
		*n_args = 0;
		break;
	}
	/* cheriabi_mount */
	case 21: {
		struct cheriabi_mount_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->type; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[2] = p->flags; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_unmount */
	case 22: {
		struct cheriabi_unmount_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_ptrace */
	case 26: {
		struct cheriabi_ptrace_args *p = params;
		iarg[0] = p->req; /* int */
		iarg[1] = p->pid; /* pid_t */
		uarg[2] = (__cheri_addr intptr_t) p->addr; /* char * __capability */
		iarg[3] = p->data; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_recvmsg */
	case 27: {
		struct cheriabi_recvmsg_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->msg; /* struct msghdr_c * __capability */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_sendmsg */
	case 28: {
		struct cheriabi_sendmsg_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->msg; /* const struct msghdr_c * __capability */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_recvfrom */
	case 29: {
		struct cheriabi_recvfrom_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* void * __capability */
		uarg[2] = p->len; /* size_t */
		iarg[3] = p->flags; /* int */
		uarg[4] = (__cheri_addr intptr_t) p->from; /* struct sockaddr * __capability */
		uarg[5] = (__cheri_addr intptr_t) p->fromlenaddr; /* __socklen_t * __capability */
		*n_args = 6;
		break;
	}
	/* cheriabi_accept */
	case 30: {
		struct cheriabi_accept_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->name; /* struct sockaddr * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->anamelen; /* __socklen_t * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_getpeername */
	case 31: {
		struct cheriabi_getpeername_args *p = params;
		iarg[0] = p->fdes; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->asa; /* struct sockaddr * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->alen; /* __socklen_t * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_getsockname */
	case 32: {
		struct cheriabi_getsockname_args *p = params;
		iarg[0] = p->fdes; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->asa; /* struct sockaddr * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->alen; /* __socklen_t * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_access */
	case 33: {
		struct cheriabi_access_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->amode; /* int */
		*n_args = 2;
		break;
	}
	/* cheriabi_chflags */
	case 34: {
		struct cheriabi_chflags_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_profil */
	case 44: {
		struct cheriabi_profil_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->samples; /* char * __capability */
		uarg[1] = p->size; /* size_t */
		uarg[2] = p->offset; /* size_t */
		uarg[3] = p->scale; /* u_int */
		*n_args = 4;
		break;
	}
	/* cheriabi_ktrace */
	case 45: {
		struct cheriabi_ktrace_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fname; /* const char * __capability */
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
	/* cheriabi_getlogin */
	case 49: {
		struct cheriabi_getlogin_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->namebuf; /* char * __capability */
		uarg[1] = p->namelen; /* u_int */
		*n_args = 2;
		break;
	}
	/* cheriabi_setlogin */
	case 50: {
		struct cheriabi_setlogin_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->namebuf; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_acct */
	case 51: {
		struct cheriabi_acct_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_sigaltstack */
	case 53: {
		struct cheriabi_sigaltstack_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->ss; /* const struct sigaltstack_c * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->oss; /* struct sigaltstack_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_ioctl */
	case 54: {
		struct cheriabi_ioctl_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = p->com; /* u_long */
		uarg[2] = (__cheri_addr intptr_t) p->data; /* char * __capability */
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
	/* cheriabi_revoke */
	case 56: {
		struct cheriabi_revoke_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_symlink */
	case 57: {
		struct cheriabi_symlink_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->link; /* const char * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_readlink */
	case 58: {
		struct cheriabi_readlink_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* char * __capability */
		uarg[2] = p->count; /* size_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_execve */
	case 59: {
		struct cheriabi_execve_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fname; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->argv; /* char * __capability * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->envv; /* char * __capability * __capability */
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
	/* cheriabi_chroot */
	case 61: {
		struct cheriabi_chroot_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_msync */
	case 65: {
		struct cheriabi_msync_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* void * __capability */
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
	/* cheriabi_munmap */
	case 73: {
		struct cheriabi_munmap_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* void * __capability */
		uarg[1] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_mprotect */
	case 74: {
		struct cheriabi_mprotect_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* const void * __capability */
		uarg[1] = p->len; /* size_t */
		iarg[2] = p->prot; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_madvise */
	case 75: {
		struct cheriabi_madvise_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* void * __capability */
		uarg[1] = p->len; /* size_t */
		iarg[2] = p->behav; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_mincore */
	case 78: {
		struct cheriabi_mincore_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* const void * __capability */
		uarg[1] = p->len; /* size_t */
		uarg[2] = (__cheri_addr intptr_t) p->vec; /* char * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_getgroups */
	case 79: {
		struct cheriabi_getgroups_args *p = params;
		uarg[0] = p->gidsetsize; /* u_int */
		uarg[1] = (__cheri_addr intptr_t) p->gidset; /* gid_t * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_setgroups */
	case 80: {
		struct cheriabi_setgroups_args *p = params;
		uarg[0] = p->gidsetsize; /* u_int */
		uarg[1] = (__cheri_addr intptr_t) p->gidset; /* const gid_t * __capability */
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
	/* cheriabi_setitimer */
	case 83: {
		struct cheriabi_setitimer_args *p = params;
		iarg[0] = p->which; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->itv; /* const struct itimerval * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->oitv; /* struct itimerval * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_swapon */
	case 85: {
		struct cheriabi_swapon_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_getitimer */
	case 86: {
		struct cheriabi_getitimer_args *p = params;
		iarg[0] = p->which; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->itv; /* struct itimerval * __capability */
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
	/* cheriabi_fcntl */
	case 92: {
		struct cheriabi_fcntl_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->arg; /* intcap_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_select */
	case 93: {
		struct cheriabi_select_args *p = params;
		iarg[0] = p->nd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->in; /* fd_set * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->ou; /* fd_set * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->ex; /* fd_set * __capability */
		uarg[4] = (__cheri_addr intptr_t) p->tv; /* struct timeval * __capability */
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
	/* cheriabi_connect */
	case 98: {
		struct cheriabi_connect_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->name; /* const struct sockaddr * __capability */
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
	/* cheriabi_bind */
	case 104: {
		struct cheriabi_bind_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->name; /* const struct sockaddr * __capability */
		iarg[2] = p->namelen; /* __socklen_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_setsockopt */
	case 105: {
		struct cheriabi_setsockopt_args *p = params;
		iarg[0] = p->s; /* int */
		iarg[1] = p->level; /* int */
		iarg[2] = p->name; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->val; /* const void * __capability */
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
	/* cheriabi_gettimeofday */
	case 116: {
		struct cheriabi_gettimeofday_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->tp; /* struct timeval * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->tzp; /* struct timezone * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_getrusage */
	case 117: {
		struct cheriabi_getrusage_args *p = params;
		iarg[0] = p->who; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->rusage; /* struct rusage * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_getsockopt */
	case 118: {
		struct cheriabi_getsockopt_args *p = params;
		iarg[0] = p->s; /* int */
		iarg[1] = p->level; /* int */
		iarg[2] = p->name; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->val; /* void * __capability */
		uarg[4] = (__cheri_addr intptr_t) p->avalsize; /* __socklen_t * __capability */
		*n_args = 5;
		break;
	}
	/* cheriabi_readv */
	case 120: {
		struct cheriabi_readv_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->iovp; /* struct iovec_c * __capability */
		uarg[2] = p->iovcnt; /* u_int */
		*n_args = 3;
		break;
	}
	/* cheriabi_writev */
	case 121: {
		struct cheriabi_writev_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->iovp; /* struct iovec_c * __capability */
		uarg[2] = p->iovcnt; /* u_int */
		*n_args = 3;
		break;
	}
	/* cheriabi_settimeofday */
	case 122: {
		struct cheriabi_settimeofday_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->tv; /* const struct timeval * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->tzp; /* const struct timezone * __capability */
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
	/* cheriabi_rename */
	case 128: {
		struct cheriabi_rename_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->from; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->to; /* const char * __capability */
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
	/* cheriabi_mkfifo */
	case 132: {
		struct cheriabi_mkfifo_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_sendto */
	case 133: {
		struct cheriabi_sendto_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* const void * __capability */
		uarg[2] = p->len; /* size_t */
		iarg[3] = p->flags; /* int */
		uarg[4] = (__cheri_addr intptr_t) p->to; /* const struct sockaddr * __capability */
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
	/* cheriabi_socketpair */
	case 135: {
		struct cheriabi_socketpair_args *p = params;
		iarg[0] = p->domain; /* int */
		iarg[1] = p->type; /* int */
		iarg[2] = p->protocol; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->rsv; /* int * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_mkdir */
	case 136: {
		struct cheriabi_mkdir_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_rmdir */
	case 137: {
		struct cheriabi_rmdir_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_utimes */
	case 138: {
		struct cheriabi_utimes_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->tptr; /* const struct timeval * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_adjtime */
	case 140: {
		struct cheriabi_adjtime_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->delta; /* const struct timeval * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->olddelta; /* struct timeval * __capability */
		*n_args = 2;
		break;
	}
	/* setsid */
	case 147: {
		*n_args = 0;
		break;
	}
	/* cheriabi_quotactl */
	case 148: {
		struct cheriabi_quotactl_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->cmd; /* int */
		iarg[2] = p->uid; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->arg; /* void * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_nlm_syscall */
	case 154: {
		struct cheriabi_nlm_syscall_args *p = params;
		iarg[0] = p->debug_level; /* int */
		iarg[1] = p->grace_period; /* int */
		iarg[2] = p->addr_count; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->addrs; /* char * __capability * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_nfssvc */
	case 155: {
		struct cheriabi_nfssvc_args *p = params;
		iarg[0] = p->flag; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->argp; /* void * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_lgetfh */
	case 160: {
		struct cheriabi_lgetfh_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fname; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->fhp; /* struct fhandle * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_getfh */
	case 161: {
		struct cheriabi_getfh_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fname; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->fhp; /* struct fhandle * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_sysarch */
	case 165: {
		struct cheriabi_sysarch_args *p = params;
		iarg[0] = p->op; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->parms; /* char * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_rtprio */
	case 166: {
		struct cheriabi_rtprio_args *p = params;
		iarg[0] = p->function; /* int */
		iarg[1] = p->pid; /* pid_t */
		uarg[2] = (__cheri_addr intptr_t) p->rtp; /* struct rtprio * __capability */
		*n_args = 3;
		break;
	}
	/* setfib */
	case 175: {
		struct setfib_args *p = params;
		iarg[0] = p->fibnum; /* int */
		*n_args = 1;
		break;
	}
	/* cheriabi_ntp_adjtime */
	case 176: {
		struct cheriabi_ntp_adjtime_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->tp; /* struct timex * __capability */
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
	/* cheriabi_pathconf */
	case 191: {
		struct cheriabi_pathconf_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_getrlimit */
	case 194: {
		struct cheriabi___getrlimit_args *p = params;
		uarg[0] = p->which; /* u_int */
		uarg[1] = (__cheri_addr intptr_t) p->rlp; /* struct rlimit * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_setrlimit */
	case 195: {
		struct cheriabi___setrlimit_args *p = params;
		uarg[0] = p->which; /* u_int */
		uarg[1] = (__cheri_addr intptr_t) p->rlp; /* struct rlimit * __capability */
		*n_args = 2;
		break;
	}
	/* nosys */
	case 198: {
		*n_args = 0;
		break;
	}
	/* cheriabi___sysctl */
	case 202: {
		struct cheriabi___sysctl_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->name; /* int * __capability */
		uarg[1] = p->namelen; /* u_int */
		uarg[2] = (__cheri_addr intptr_t) p->old; /* void * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->oldlenp; /* size_t * __capability */
		uarg[4] = (__cheri_addr intptr_t) p->new; /* const void * __capability */
		uarg[5] = p->newlen; /* size_t */
		*n_args = 6;
		break;
	}
	/* cheriabi_mlock */
	case 203: {
		struct cheriabi_mlock_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* const void * __capability */
		uarg[1] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_munlock */
	case 204: {
		struct cheriabi_munlock_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* const void * __capability */
		uarg[1] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_undelete */
	case 205: {
		struct cheriabi_undelete_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_futimes */
	case 206: {
		struct cheriabi_futimes_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->tptr; /* const struct timeval * __capability */
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
	/* cheriabi_poll */
	case 209: {
		struct cheriabi_poll_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fds; /* struct pollfd * __capability */
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
	/* cheriabi_semop */
	case 222: {
		struct cheriabi_semop_args *p = params;
		iarg[0] = p->semid; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->sops; /* struct sembuf * __capability */
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
	/* cheriabi_msgsnd */
	case 226: {
		struct cheriabi_msgsnd_args *p = params;
		iarg[0] = p->msqid; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->msgp; /* const void * __capability */
		uarg[2] = p->msgsz; /* size_t */
		iarg[3] = p->msgflg; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_msgrcv */
	case 227: {
		struct cheriabi_msgrcv_args *p = params;
		iarg[0] = p->msqid; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->msgp; /* void * __capability */
		uarg[2] = p->msgsz; /* size_t */
		iarg[3] = p->msgtyp; /* long */
		iarg[4] = p->msgflg; /* int */
		*n_args = 5;
		break;
	}
	/* cheriabi_shmat */
	case 228: {
		struct cheriabi_shmat_args *p = params;
		iarg[0] = p->shmid; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->shmaddr; /* const void * __capability */
		iarg[2] = p->shmflg; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_shmdt */
	case 230: {
		struct cheriabi_shmdt_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->shmaddr; /* const void * __capability */
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
	/* cheriabi_clock_gettime */
	case 232: {
		struct cheriabi_clock_gettime_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		uarg[1] = (__cheri_addr intptr_t) p->tp; /* struct timespec * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_clock_settime */
	case 233: {
		struct cheriabi_clock_settime_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		uarg[1] = (__cheri_addr intptr_t) p->tp; /* const struct timespec * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_clock_getres */
	case 234: {
		struct cheriabi_clock_getres_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		uarg[1] = (__cheri_addr intptr_t) p->tp; /* struct timespec * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_ktimer_create */
	case 235: {
		struct cheriabi_ktimer_create_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		uarg[1] = (__cheri_addr intptr_t) p->evp; /* struct sigevent_c * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->timerid; /* int * __capability */
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
	/* cheriabi_ktimer_settime */
	case 237: {
		struct cheriabi_ktimer_settime_args *p = params;
		iarg[0] = p->timerid; /* int */
		iarg[1] = p->flags; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->value; /* const struct itimerspec * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->ovalue; /* struct itimerspec * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_ktimer_gettime */
	case 238: {
		struct cheriabi_ktimer_gettime_args *p = params;
		iarg[0] = p->timerid; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->value; /* struct itimerspec * __capability */
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
	/* cheriabi_nanosleep */
	case 240: {
		struct cheriabi_nanosleep_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->rqtp; /* const struct timespec * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->rmtp; /* struct timespec * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_ffclock_getcounter */
	case 241: {
		struct cheriabi_ffclock_getcounter_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->ffcount; /* ffcounter * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_ffclock_setestimate */
	case 242: {
		struct cheriabi_ffclock_setestimate_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->cest; /* struct ffclock_estimate * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_ffclock_getestimate */
	case 243: {
		struct cheriabi_ffclock_getestimate_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->cest; /* struct ffclock_estimate * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_clock_nanosleep */
	case 244: {
		struct cheriabi_clock_nanosleep_args *p = params;
		iarg[0] = p->clock_id; /* clockid_t */
		iarg[1] = p->flags; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->rqtp; /* const struct timespec * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->rmtp; /* struct timespec * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_clock_getcpuclockid2 */
	case 247: {
		struct cheriabi_clock_getcpuclockid2_args *p = params;
		iarg[0] = p->id; /* id_t */
		iarg[1] = p->which; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->clock_id; /* clockid_t * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_ntp_gettime */
	case 248: {
		struct cheriabi_ntp_gettime_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->ntvp; /* struct ntptimeval * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_minherit */
	case 250: {
		struct cheriabi_minherit_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* void * __capability */
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
	/* cheriabi_lchown */
	case 254: {
		struct cheriabi_lchown_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->uid; /* int */
		iarg[2] = p->gid; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_aio_read */
	case 255: {
		struct cheriabi_aio_read_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_aio_write */
	case 256: {
		struct cheriabi_aio_write_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_lio_listio */
	case 257: {
		struct cheriabi_lio_listio_args *p = params;
		iarg[0] = p->mode; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->acb_list; /* struct aiocb_c * __capability const * __capability */
		iarg[2] = p->nent; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->sig; /* struct sigevent_c * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_kbounce */
	case 258: {
		struct cheriabi_kbounce_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->src; /* const void * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->dst; /* void * __capability */
		uarg[2] = p->len; /* size_t */
		iarg[3] = p->flags; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_flag_captured */
	case 259: {
		struct cheriabi_flag_captured_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->message; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_lchmod */
	case 274: {
		struct cheriabi_lchmod_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->mode; /* mode_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_lutimes */
	case 276: {
		struct cheriabi_lutimes_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->tptr; /* const struct timeval * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_preadv */
	case 289: {
		struct cheriabi_preadv_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->iovp; /* struct iovec_c * __capability */
		uarg[2] = p->iovcnt; /* u_int */
		iarg[3] = p->offset; /* off_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_pwritev */
	case 290: {
		struct cheriabi_pwritev_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->iovp; /* struct iovec_c * __capability */
		uarg[2] = p->iovcnt; /* u_int */
		iarg[3] = p->offset; /* off_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_fhopen */
	case 298: {
		struct cheriabi_fhopen_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->u_fhp; /* const struct fhandle * __capability */
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
	/* cheriabi_modstat */
	case 301: {
		struct cheriabi_modstat_args *p = params;
		iarg[0] = p->modid; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->stat; /* struct module_stat * __capability */
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
	/* cheriabi_modfind */
	case 303: {
		struct cheriabi_modfind_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_kldload */
	case 304: {
		struct cheriabi_kldload_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->file; /* const char * __capability */
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
	/* cheriabi_kldfind */
	case 306: {
		struct cheriabi_kldfind_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->file; /* const char * __capability */
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
	/* cheriabi_kldstat */
	case 308: {
		struct cheriabi_kldstat_args *p = params;
		iarg[0] = p->fileid; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->stat; /* struct kld_file_stat_c * __capability */
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
	/* cheriabi_aio_return */
	case 314: {
		struct cheriabi_aio_return_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_aio_suspend */
	case 315: {
		struct cheriabi_aio_suspend_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability const * __capability */
		iarg[1] = p->nent; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->timeout; /* const struct timespec * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_aio_cancel */
	case 316: {
		struct cheriabi_aio_cancel_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_aio_error */
	case 317: {
		struct cheriabi_aio_error_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability */
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
	/* cheriabi___getcwd */
	case 326: {
		struct cheriabi___getcwd_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->buf; /* char * __capability */
		uarg[1] = p->buflen; /* size_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_sched_setparam */
	case 327: {
		struct cheriabi_sched_setparam_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		uarg[1] = (__cheri_addr intptr_t) p->param; /* const struct sched_param * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_sched_getparam */
	case 328: {
		struct cheriabi_sched_getparam_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		uarg[1] = (__cheri_addr intptr_t) p->param; /* struct sched_param * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_sched_setscheduler */
	case 329: {
		struct cheriabi_sched_setscheduler_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		iarg[1] = p->policy; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->param; /* const struct sched_param * __capability */
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
	/* cheriabi_sched_rr_get_interval */
	case 334: {
		struct cheriabi_sched_rr_get_interval_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		uarg[1] = (__cheri_addr intptr_t) p->interval; /* struct timespec * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_utrace */
	case 335: {
		struct cheriabi_utrace_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* const void * __capability */
		uarg[1] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_kldsym */
	case 337: {
		struct cheriabi_kldsym_args *p = params;
		iarg[0] = p->fileid; /* int */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_jail */
	case 338: {
		struct cheriabi_jail_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->jailp; /* struct jail_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_nnpfs_syscall */
	case 339: {
		struct cheriabi_nnpfs_syscall_args *p = params;
		iarg[0] = p->operation; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->a_pathP; /* char * __capability */
		iarg[2] = p->a_opcode; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->a_paramsP; /* void * __capability */
		iarg[4] = p->a_followSymlinks; /* int */
		*n_args = 5;
		break;
	}
	/* cheriabi_sigprocmask */
	case 340: {
		struct cheriabi_sigprocmask_args *p = params;
		iarg[0] = p->how; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->set; /* const sigset_t * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->oset; /* sigset_t * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_sigsuspend */
	case 341: {
		struct cheriabi_sigsuspend_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->sigmask; /* const sigset_t * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_sigpending */
	case 343: {
		struct cheriabi_sigpending_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->set; /* sigset_t * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_sigtimedwait */
	case 345: {
		struct cheriabi_sigtimedwait_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->set; /* const sigset_t * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->info; /* struct siginfo_c * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->timeout; /* const struct timespec * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_sigwaitinfo */
	case 346: {
		struct cheriabi_sigwaitinfo_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->set; /* const sigset_t * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->info; /* struct siginfo_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi___acl_get_file */
	case 347: {
		struct cheriabi___acl_get_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi___acl_set_file */
	case 348: {
		struct cheriabi___acl_set_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi___acl_get_fd */
	case 349: {
		struct cheriabi___acl_get_fd_args *p = params;
		iarg[0] = p->filedes; /* int */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi___acl_set_fd */
	case 350: {
		struct cheriabi___acl_set_fd_args *p = params;
		iarg[0] = p->filedes; /* int */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi___acl_delete_file */
	case 351: {
		struct cheriabi___acl_delete_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi___acl_aclcheck_file */
	case 353: {
		struct cheriabi___acl_aclcheck_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi___acl_aclcheck_fd */
	case 354: {
		struct cheriabi___acl_aclcheck_fd_args *p = params;
		iarg[0] = p->filedes; /* int */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_extattrctl */
	case 355: {
		struct cheriabi_extattrctl_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->filename; /* const char * __capability */
		iarg[3] = p->attrnamespace; /* int */
		uarg[4] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		*n_args = 5;
		break;
	}
	/* cheriabi_extattr_set_file */
	case 356: {
		struct cheriabi_extattr_set_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* cheriabi_extattr_get_file */
	case 357: {
		struct cheriabi_extattr_get_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* cheriabi_extattr_delete_file */
	case 358: {
		struct cheriabi_extattr_delete_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_aio_waitcomplete */
	case 359: {
		struct cheriabi_aio_waitcomplete_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->timeout; /* struct timespec * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_getresuid */
	case 360: {
		struct cheriabi_getresuid_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->ruid; /* uid_t * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->euid; /* uid_t * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->suid; /* uid_t * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_getresgid */
	case 361: {
		struct cheriabi_getresgid_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->rgid; /* gid_t * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->egid; /* gid_t * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->sgid; /* gid_t * __capability */
		*n_args = 3;
		break;
	}
	/* kqueue */
	case 362: {
		*n_args = 0;
		break;
	}
	/* cheriabi_extattr_set_fd */
	case 371: {
		struct cheriabi_extattr_set_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* cheriabi_extattr_get_fd */
	case 372: {
		struct cheriabi_extattr_get_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* cheriabi_extattr_delete_fd */
	case 373: {
		struct cheriabi_extattr_delete_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
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
	/* cheriabi_eaccess */
	case 376: {
		struct cheriabi_eaccess_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_nmount */
	case 378: {
		struct cheriabi_nmount_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->iovp; /* struct iovec_c * __capability */
		uarg[1] = p->iovcnt; /* unsigned int */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi___mac_get_proc */
	case 384: {
		struct cheriabi___mac_get_proc_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi___mac_set_proc */
	case 385: {
		struct cheriabi___mac_set_proc_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi___mac_get_fd */
	case 386: {
		struct cheriabi___mac_get_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi___mac_get_file */
	case 387: {
		struct cheriabi___mac_get_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path_p; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi___mac_set_fd */
	case 388: {
		struct cheriabi___mac_set_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi___mac_set_file */
	case 389: {
		struct cheriabi___mac_set_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path_p; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_kenv */
	case 390: {
		struct cheriabi_kenv_args *p = params;
		iarg[0] = p->what; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->value; /* char * __capability */
		iarg[3] = p->len; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_lchflags */
	case 391: {
		struct cheriabi_lchflags_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[1] = p->flags; /* u_long */
		*n_args = 2;
		break;
	}
	/* cheriabi_uuidgen */
	case 392: {
		struct cheriabi_uuidgen_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->store; /* struct uuid * __capability */
		iarg[1] = p->count; /* int */
		*n_args = 2;
		break;
	}
	/* cheriabi_sendfile */
	case 393: {
		struct cheriabi_sendfile_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->s; /* int */
		iarg[2] = p->offset; /* off_t */
		uarg[3] = p->nbytes; /* size_t */
		uarg[4] = (__cheri_addr intptr_t) p->hdtr; /* struct sf_hdtr_c * __capability */
		uarg[5] = (__cheri_addr intptr_t) p->sbytes; /* off_t * __capability */
		iarg[6] = p->flags; /* int */
		*n_args = 7;
		break;
	}
	/* cheriabi_mac_syscall */
	case 394: {
		struct cheriabi_mac_syscall_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->policy; /* const char * __capability */
		iarg[1] = p->call; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->arg; /* void * __capability */
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
	/* cheriabi_ksem_init */
	case 404: {
		struct cheriabi_ksem_init_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->idp; /* semid_t * __capability */
		uarg[1] = p->value; /* unsigned int */
		*n_args = 2;
		break;
	}
	/* cheriabi_ksem_open */
	case 405: {
		struct cheriabi_ksem_open_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->idp; /* semid_t * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		iarg[2] = p->oflag; /* int */
		iarg[3] = p->mode; /* mode_t */
		uarg[4] = p->value; /* unsigned int */
		*n_args = 5;
		break;
	}
	/* cheriabi_ksem_unlink */
	case 406: {
		struct cheriabi_ksem_unlink_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_ksem_getvalue */
	case 407: {
		struct cheriabi_ksem_getvalue_args *p = params;
		iarg[0] = p->id; /* semid_t */
		uarg[1] = (__cheri_addr intptr_t) p->val; /* int * __capability */
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
	/* cheriabi___mac_get_pid */
	case 409: {
		struct cheriabi___mac_get_pid_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		uarg[1] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi___mac_get_link */
	case 410: {
		struct cheriabi___mac_get_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path_p; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi___mac_set_link */
	case 411: {
		struct cheriabi___mac_set_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path_p; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_extattr_set_link */
	case 412: {
		struct cheriabi_extattr_set_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* cheriabi_extattr_get_link */
	case 413: {
		struct cheriabi_extattr_get_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[4] = p->nbytes; /* size_t */
		*n_args = 5;
		break;
	}
	/* cheriabi_extattr_delete_link */
	case 414: {
		struct cheriabi_extattr_delete_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->attrname; /* const char * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi___mac_execve */
	case 415: {
		struct cheriabi___mac_execve_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fname; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->argv; /* char * __capability * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->envv; /* char * __capability * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->mac_p; /* struct mac_c * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_sigaction */
	case 416: {
		struct cheriabi_sigaction_args *p = params;
		iarg[0] = p->sig; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->act; /* const struct sigaction_c * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->oact; /* struct sigaction_c * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_sigreturn */
	case 417: {
		struct cheriabi_sigreturn_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->sigcntxp; /* const struct __ucontext_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_getcontext */
	case 421: {
		struct cheriabi_getcontext_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->ucp; /* struct __ucontext_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_setcontext */
	case 422: {
		struct cheriabi_setcontext_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->ucp; /* const struct __ucontext_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_swapcontext */
	case 423: {
		struct cheriabi_swapcontext_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->oucp; /* struct __ucontext_c * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->ucp; /* const struct __ucontext_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_swapoff */
	case 424: {
		struct cheriabi_swapoff_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi___acl_get_link */
	case 425: {
		struct cheriabi___acl_get_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi___acl_set_link */
	case 426: {
		struct cheriabi___acl_set_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi___acl_delete_link */
	case 427: {
		struct cheriabi___acl_delete_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->type; /* acl_type_t */
		*n_args = 2;
		break;
	}
	/* cheriabi___acl_aclcheck_link */
	case 428: {
		struct cheriabi___acl_aclcheck_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->type; /* acl_type_t */
		uarg[2] = (__cheri_addr intptr_t) p->aclp; /* struct acl * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_sigwait */
	case 429: {
		struct cheriabi_sigwait_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->set; /* const sigset_t * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->sig; /* int * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_thr_create */
	case 430: {
		struct cheriabi_thr_create_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->ctx; /* struct __ucontext_c * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->id; /* long * __capability */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_thr_exit */
	case 431: {
		struct cheriabi_thr_exit_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->state; /* long * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_thr_self */
	case 432: {
		struct cheriabi_thr_self_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->id; /* long * __capability */
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
	/* cheriabi_extattr_list_fd */
	case 437: {
		struct cheriabi_extattr_list_fd_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[3] = p->nbytes; /* size_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_extattr_list_file */
	case 438: {
		struct cheriabi_extattr_list_file_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[3] = p->nbytes; /* size_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_extattr_list_link */
	case 439: {
		struct cheriabi_extattr_list_link_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->attrnamespace; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[3] = p->nbytes; /* size_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_ksem_timedwait */
	case 441: {
		struct cheriabi_ksem_timedwait_args *p = params;
		iarg[0] = p->id; /* semid_t */
		uarg[1] = (__cheri_addr intptr_t) p->abstime; /* const struct timespec * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_thr_suspend */
	case 442: {
		struct cheriabi_thr_suspend_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->timeout; /* const struct timespec * __capability */
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
	/* cheriabi_audit */
	case 445: {
		struct cheriabi_audit_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->record; /* const void * __capability */
		uarg[1] = p->length; /* u_int */
		*n_args = 2;
		break;
	}
	/* cheriabi_auditon */
	case 446: {
		struct cheriabi_auditon_args *p = params;
		iarg[0] = p->cmd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		uarg[2] = p->length; /* u_int */
		*n_args = 3;
		break;
	}
	/* cheriabi_getauid */
	case 447: {
		struct cheriabi_getauid_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->auid; /* uid_t * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_setauid */
	case 448: {
		struct cheriabi_setauid_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->auid; /* uid_t * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_getaudit */
	case 449: {
		struct cheriabi_getaudit_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->auditinfo; /* struct auditinfo * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_setaudit */
	case 450: {
		struct cheriabi_setaudit_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->auditinfo; /* struct auditinfo * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_getaudit_addr */
	case 451: {
		struct cheriabi_getaudit_addr_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->auditinfo_addr; /* struct auditinfo_addr * __capability */
		uarg[1] = p->length; /* u_int */
		*n_args = 2;
		break;
	}
	/* cheriabi_setaudit_addr */
	case 452: {
		struct cheriabi_setaudit_addr_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->auditinfo_addr; /* struct auditinfo_addr * __capability */
		uarg[1] = p->length; /* u_int */
		*n_args = 2;
		break;
	}
	/* cheriabi_auditctl */
	case 453: {
		struct cheriabi_auditctl_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi__umtx_op */
	case 454: {
		struct cheriabi__umtx_op_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->obj; /* void * __capability */
		iarg[1] = p->op; /* int */
		uarg[2] = p->val; /* u_long */
		uarg[3] = (__cheri_addr intptr_t) p->uaddr1; /* void * __capability */
		uarg[4] = (__cheri_addr intptr_t) p->uaddr2; /* void * __capability */
		*n_args = 5;
		break;
	}
	/* cheriabi_thr_new */
	case 455: {
		struct cheriabi_thr_new_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->param; /* struct thr_param_c * __capability */
		iarg[1] = p->param_size; /* int */
		*n_args = 2;
		break;
	}
	/* cheriabi_sigqueue */
	case 456: {
		struct cheriabi_sigqueue_args *p = params;
		iarg[0] = p->pid; /* pid_t */
		iarg[1] = p->signum; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->value; /* void * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_kmq_open */
	case 457: {
		struct cheriabi_kmq_open_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->flags; /* int */
		iarg[2] = p->mode; /* mode_t */
		uarg[3] = (__cheri_addr intptr_t) p->attr; /* const struct mq_attr * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_kmq_setattr */
	case 458: {
		struct cheriabi_kmq_setattr_args *p = params;
		iarg[0] = p->mqd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->attr; /* const struct mq_attr * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->oattr; /* struct mq_attr * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_kmq_timedreceive */
	case 459: {
		struct cheriabi_kmq_timedreceive_args *p = params;
		iarg[0] = p->mqd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->msg_ptr; /* char * __capability */
		uarg[2] = p->msg_len; /* size_t */
		uarg[3] = (__cheri_addr intptr_t) p->msg_prio; /* unsigned * __capability */
		uarg[4] = (__cheri_addr intptr_t) p->abs_timeout; /* const struct timespec * __capability */
		*n_args = 5;
		break;
	}
	/* cheriabi_kmq_timedsend */
	case 460: {
		struct cheriabi_kmq_timedsend_args *p = params;
		iarg[0] = p->mqd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->msg_ptr; /* const char * __capability */
		uarg[2] = p->msg_len; /* size_t */
		uarg[3] = p->msg_prio; /* unsigned */
		uarg[4] = (__cheri_addr intptr_t) p->abs_timeout; /* const struct timespec * __capability */
		*n_args = 5;
		break;
	}
	/* cheriabi_kmq_notify */
	case 461: {
		struct cheriabi_kmq_notify_args *p = params;
		iarg[0] = p->mqd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->sigev; /* const struct sigevent_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_kmq_unlink */
	case 462: {
		struct cheriabi_kmq_unlink_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_abort2 */
	case 463: {
		struct cheriabi_abort2_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->why; /* const char * __capability */
		iarg[1] = p->nargs; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->args; /* void * __capability * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_thr_set_name */
	case 464: {
		struct cheriabi_thr_set_name_args *p = params;
		iarg[0] = p->id; /* long */
		uarg[1] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_aio_fsync */
	case 465: {
		struct cheriabi_aio_fsync_args *p = params;
		iarg[0] = p->op; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_rtprio_thread */
	case 466: {
		struct cheriabi_rtprio_thread_args *p = params;
		iarg[0] = p->function; /* int */
		iarg[1] = p->lwpid; /* lwpid_t */
		uarg[2] = (__cheri_addr intptr_t) p->rtp; /* struct rtprio * __capability */
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
	/* cheriabi_sctp_generic_sendmsg */
	case 472: {
		struct cheriabi_sctp_generic_sendmsg_args *p = params;
		iarg[0] = p->sd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->msg; /* void * __capability */
		iarg[2] = p->mlen; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->to; /* const struct sockaddr * __capability */
		iarg[4] = p->tolen; /* __socklen_t */
		uarg[5] = (__cheri_addr intptr_t) p->sinfo; /* struct sctp_sndrcvinfo * __capability */
		iarg[6] = p->flags; /* int */
		*n_args = 7;
		break;
	}
	/* cheriabi_sctp_generic_sendmsg_iov */
	case 473: {
		struct cheriabi_sctp_generic_sendmsg_iov_args *p = params;
		iarg[0] = p->sd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->iov; /* struct iovec_c * __capability */
		iarg[2] = p->iovlen; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->to; /* const struct sockaddr * __capability */
		iarg[4] = p->tolen; /* __socklen_t */
		uarg[5] = (__cheri_addr intptr_t) p->sinfo; /* struct sctp_sndrcvinfo * __capability */
		iarg[6] = p->flags; /* int */
		*n_args = 7;
		break;
	}
	/* cheriabi_sctp_generic_recvmsg */
	case 474: {
		struct cheriabi_sctp_generic_recvmsg_args *p = params;
		iarg[0] = p->sd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->iov; /* struct iovec_c * __capability */
		iarg[2] = p->iovlen; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->from; /* struct sockaddr * __capability */
		uarg[4] = (__cheri_addr intptr_t) p->fromlenaddr; /* __socklen_t * __capability */
		uarg[5] = (__cheri_addr intptr_t) p->sinfo; /* struct sctp_sndrcvinfo * __capability */
		uarg[6] = (__cheri_addr intptr_t) p->msg_flags; /* int * __capability */
		*n_args = 7;
		break;
	}
	/* cheriabi_pread */
	case 475: {
		struct cheriabi_pread_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* void * __capability */
		uarg[2] = p->nbyte; /* size_t */
		iarg[3] = p->offset; /* off_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_pwrite */
	case 476: {
		struct cheriabi_pwrite_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* const void * __capability */
		uarg[2] = p->nbyte; /* size_t */
		iarg[3] = p->offset; /* off_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_mmap */
	case 477: {
		struct cheriabi_mmap_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->addr; /* void * __capability */
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
	/* cheriabi_truncate */
	case 479: {
		struct cheriabi_truncate_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_shm_unlink */
	case 483: {
		struct cheriabi_shm_unlink_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_cpuset */
	case 484: {
		struct cheriabi_cpuset_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->setid; /* cpusetid_t * __capability */
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
	/* cheriabi_cpuset_getid */
	case 486: {
		struct cheriabi_cpuset_getid_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = (__cheri_addr intptr_t) p->setid; /* cpusetid_t * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_cpuset_getaffinity */
	case 487: {
		struct cheriabi_cpuset_getaffinity_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = p->cpusetsize; /* size_t */
		uarg[4] = (__cheri_addr intptr_t) p->mask; /* cpuset_t * __capability */
		*n_args = 5;
		break;
	}
	/* cheriabi_cpuset_setaffinity */
	case 488: {
		struct cheriabi_cpuset_setaffinity_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = p->cpusetsize; /* size_t */
		uarg[4] = (__cheri_addr intptr_t) p->mask; /* const cpuset_t * __capability */
		*n_args = 5;
		break;
	}
	/* cheriabi_faccessat */
	case 489: {
		struct cheriabi_faccessat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[2] = p->amode; /* int */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_fchmodat */
	case 490: {
		struct cheriabi_fchmodat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[2] = p->mode; /* mode_t */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_fchownat */
	case 491: {
		struct cheriabi_fchownat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[2] = p->uid; /* uid_t */
		iarg[3] = p->gid; /* gid_t */
		iarg[4] = p->flag; /* int */
		*n_args = 5;
		break;
	}
	/* cheriabi_fexecve */
	case 492: {
		struct cheriabi_fexecve_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->argv; /* char * __capability * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->envv; /* char * __capability * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_futimesat */
	case 494: {
		struct cheriabi_futimesat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->times; /* const struct timeval * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_linkat */
	case 495: {
		struct cheriabi_linkat_args *p = params;
		iarg[0] = p->fd1; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path1; /* const char * __capability */
		iarg[2] = p->fd2; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->path2; /* const char * __capability */
		iarg[4] = p->flag; /* int */
		*n_args = 5;
		break;
	}
	/* cheriabi_mkdirat */
	case 496: {
		struct cheriabi_mkdirat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[2] = p->mode; /* mode_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_mkfifoat */
	case 497: {
		struct cheriabi_mkfifoat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[2] = p->mode; /* mode_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_openat */
	case 499: {
		struct cheriabi_openat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[2] = p->flag; /* int */
		iarg[3] = p->mode; /* mode_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_readlinkat */
	case 500: {
		struct cheriabi_readlinkat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->buf; /* char * __capability */
		uarg[3] = p->bufsize; /* size_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_renameat */
	case 501: {
		struct cheriabi_renameat_args *p = params;
		iarg[0] = p->oldfd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->old; /* const char * __capability */
		iarg[2] = p->newfd; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->new; /* const char * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_symlinkat */
	case 502: {
		struct cheriabi_symlinkat_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path1; /* const char * __capability */
		iarg[1] = p->fd; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->path2; /* const char * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_unlinkat */
	case 503: {
		struct cheriabi_unlinkat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_gssd_syscall */
	case 505: {
		struct cheriabi_gssd_syscall_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_jail_get */
	case 506: {
		struct cheriabi_jail_get_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->iovp; /* struct iovec_c * __capability */
		uarg[1] = p->iovcnt; /* unsigned int */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_jail_set */
	case 507: {
		struct cheriabi_jail_set_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->iovp; /* struct iovec_c * __capability */
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
	/* cheriabi___semctl */
	case 510: {
		struct cheriabi___semctl_args *p = params;
		iarg[0] = p->semid; /* int */
		iarg[1] = p->semnum; /* int */
		iarg[2] = p->cmd; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->arg; /* union semun_c * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_msgctl */
	case 511: {
		struct cheriabi_msgctl_args *p = params;
		iarg[0] = p->msqid; /* int */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->buf; /* struct msqid_ds_c * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_shmctl */
	case 512: {
		struct cheriabi_shmctl_args *p = params;
		iarg[0] = p->shmid; /* int */
		iarg[1] = p->cmd; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->buf; /* struct shmid_ds * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_lpathconf */
	case 513: {
		struct cheriabi_lpathconf_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->name; /* int */
		*n_args = 2;
		break;
	}
	/* cheriabi___cap_rights_get */
	case 515: {
		struct cheriabi___cap_rights_get_args *p = params;
		iarg[0] = p->version; /* int */
		iarg[1] = p->fd; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->rightsp; /* cap_rights_t * __capability */
		*n_args = 3;
		break;
	}
	/* cap_enter */
	case 516: {
		*n_args = 0;
		break;
	}
	/* cheriabi_cap_getmode */
	case 517: {
		struct cheriabi_cap_getmode_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->modep; /* u_int * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_pdfork */
	case 518: {
		struct cheriabi_pdfork_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fdp; /* int * __capability */
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
	/* cheriabi_pdgetpid */
	case 520: {
		struct cheriabi_pdgetpid_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->pidp; /* pid_t * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_pselect */
	case 522: {
		struct cheriabi_pselect_args *p = params;
		iarg[0] = p->nd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->in; /* fd_set * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->ou; /* fd_set * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->ex; /* fd_set * __capability */
		uarg[4] = (__cheri_addr intptr_t) p->ts; /* const struct timespec * __capability */
		uarg[5] = (__cheri_addr intptr_t) p->sm; /* const sigset_t * __capability */
		*n_args = 6;
		break;
	}
	/* cheriabi_getloginclass */
	case 523: {
		struct cheriabi_getloginclass_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->namebuf; /* char * __capability */
		uarg[1] = p->namelen; /* size_t */
		*n_args = 2;
		break;
	}
	/* cheriabi_setloginclass */
	case 524: {
		struct cheriabi_setloginclass_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->namebuf; /* const char * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_rctl_get_racct */
	case 525: {
		struct cheriabi_rctl_get_racct_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->inbufp; /* const void * __capability */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (__cheri_addr intptr_t) p->outbufp; /* void * __capability */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_rctl_get_rules */
	case 526: {
		struct cheriabi_rctl_get_rules_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->inbufp; /* const void * __capability */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (__cheri_addr intptr_t) p->outbufp; /* void * __capability */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_rctl_get_limits */
	case 527: {
		struct cheriabi_rctl_get_limits_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->inbufp; /* const void * __capability */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (__cheri_addr intptr_t) p->outbufp; /* void * __capability */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_rctl_add_rule */
	case 528: {
		struct cheriabi_rctl_add_rule_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->inbufp; /* const void * __capability */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (__cheri_addr intptr_t) p->outbufp; /* void * __capability */
		uarg[3] = p->outbuflen; /* size_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_rctl_remove_rule */
	case 529: {
		struct cheriabi_rctl_remove_rule_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->inbufp; /* const void * __capability */
		uarg[1] = p->inbuflen; /* size_t */
		uarg[2] = (__cheri_addr intptr_t) p->outbufp; /* void * __capability */
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
	/* cheriabi_wait6 */
	case 532: {
		struct cheriabi_wait6_args *p = params;
		iarg[0] = p->idtype; /* idtype_t */
		iarg[1] = p->id; /* id_t */
		uarg[2] = (__cheri_addr intptr_t) p->status; /* int * __capability */
		iarg[3] = p->options; /* int */
		uarg[4] = (__cheri_addr intptr_t) p->wrusage; /* struct __wrusage * __capability */
		uarg[5] = (__cheri_addr intptr_t) p->info; /* struct siginfo_c * __capability */
		*n_args = 6;
		break;
	}
	/* cheriabi_cap_rights_limit */
	case 533: {
		struct cheriabi_cap_rights_limit_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->rightsp; /* cap_rights_t * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_cap_ioctls_limit */
	case 534: {
		struct cheriabi_cap_ioctls_limit_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->cmds; /* const u_long * __capability */
		uarg[2] = p->ncmds; /* size_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_cap_ioctls_get */
	case 535: {
		struct cheriabi_cap_ioctls_get_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->cmds; /* u_long * __capability */
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
	/* cheriabi_cap_fcntls_get */
	case 537: {
		struct cheriabi_cap_fcntls_get_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->fcntlrightsp; /* uint32_t * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_bindat */
	case 538: {
		struct cheriabi_bindat_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->s; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->name; /* const struct sockaddr * __capability */
		iarg[3] = p->namelen; /* __socklen_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_connectat */
	case 539: {
		struct cheriabi_connectat_args *p = params;
		iarg[0] = p->fd; /* int */
		iarg[1] = p->s; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->name; /* const struct sockaddr * __capability */
		iarg[3] = p->namelen; /* __socklen_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_chflagsat */
	case 540: {
		struct cheriabi_chflagsat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[2] = p->flags; /* u_long */
		iarg[3] = p->atflag; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_accept4 */
	case 541: {
		struct cheriabi_accept4_args *p = params;
		iarg[0] = p->s; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->name; /* struct sockaddr * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->anamelen; /* __socklen_t * __capability */
		iarg[3] = p->flags; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_pipe2 */
	case 542: {
		struct cheriabi_pipe2_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fildes; /* int * __capability */
		iarg[1] = p->flags; /* int */
		*n_args = 2;
		break;
	}
	/* cheriabi_aio_mlock */
	case 543: {
		struct cheriabi_aio_mlock_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->aiocbp; /* struct aiocb_c * __capability */
		*n_args = 1;
		break;
	}
	/* cheriabi_procctl */
	case 544: {
		struct cheriabi_procctl_args *p = params;
		iarg[0] = p->idtype; /* idtype_t */
		iarg[1] = p->id; /* id_t */
		iarg[2] = p->com; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->data; /* void * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_ppoll */
	case 545: {
		struct cheriabi_ppoll_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fds; /* struct pollfd * __capability */
		uarg[1] = p->nfds; /* u_int */
		uarg[2] = (__cheri_addr intptr_t) p->ts; /* const struct timespec * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->set; /* const sigset_t * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_futimens */
	case 546: {
		struct cheriabi_futimens_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->times; /* const struct timespec * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_utimensat */
	case 547: {
		struct cheriabi_utimensat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->times; /* const struct timespec * __capability */
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
	/* cheriabi_fstat */
	case 551: {
		struct cheriabi_fstat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->sb; /* struct stat * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_fstatat */
	case 552: {
		struct cheriabi_fstatat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->buf; /* struct stat * __capability */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_fhstat */
	case 553: {
		struct cheriabi_fhstat_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->u_fhp; /* const struct fhandle * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->sb; /* struct stat * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_getdirentries */
	case 554: {
		struct cheriabi_getdirentries_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* char * __capability */
		uarg[2] = p->count; /* size_t */
		uarg[3] = (__cheri_addr intptr_t) p->basep; /* off_t * __capability */
		*n_args = 4;
		break;
	}
	/* cheriabi_statfs */
	case 555: {
		struct cheriabi_statfs_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* struct statfs * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_fstatfs */
	case 556: {
		struct cheriabi_fstatfs_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* struct statfs * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_getfsstat */
	case 557: {
		struct cheriabi_getfsstat_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->buf; /* struct statfs * __capability */
		iarg[1] = p->bufsize; /* long */
		iarg[2] = p->mode; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_fhstatfs */
	case 558: {
		struct cheriabi_fhstatfs_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->u_fhp; /* const struct fhandle * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* struct statfs * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_mknodat */
	case 559: {
		struct cheriabi_mknodat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[2] = p->mode; /* mode_t */
		iarg[3] = p->dev; /* dev_t */
		*n_args = 4;
		break;
	}
	/* cheriabi_kevent */
	case 560: {
		struct cheriabi_kevent_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->changelist; /* const struct kevent_c * __capability */
		iarg[2] = p->nchanges; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->eventlist; /* struct kevent_c * __capability */
		iarg[4] = p->nevents; /* int */
		uarg[5] = (__cheri_addr intptr_t) p->timeout; /* const struct timespec * __capability */
		*n_args = 6;
		break;
	}
	/* cheriabi_cpuset_getdomain */
	case 561: {
		struct cheriabi_cpuset_getdomain_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = p->domainsetsize; /* size_t */
		uarg[4] = (__cheri_addr intptr_t) p->mask; /* domainset_t * __capability */
		uarg[5] = (__cheri_addr intptr_t) p->policy; /* int * __capability */
		*n_args = 6;
		break;
	}
	/* cheriabi_cpuset_setdomain */
	case 562: {
		struct cheriabi_cpuset_setdomain_args *p = params;
		iarg[0] = p->level; /* cpulevel_t */
		iarg[1] = p->which; /* cpuwhich_t */
		iarg[2] = p->id; /* id_t */
		uarg[3] = p->domainsetsize; /* size_t */
		uarg[4] = (__cheri_addr intptr_t) p->mask; /* domainset_t * __capability */
		iarg[5] = p->policy; /* int */
		*n_args = 6;
		break;
	}
	/* cheriabi_getrandom */
	case 563: {
		struct cheriabi_getrandom_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->buf; /* void * __capability */
		uarg[1] = p->buflen; /* size_t */
		uarg[2] = p->flags; /* unsigned int */
		*n_args = 3;
		break;
	}
	/* cheriabi_getfhat */
	case 564: {
		struct cheriabi_getfhat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* char * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->fhp; /* struct fhandle * __capability */
		iarg[3] = p->flags; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_fhlink */
	case 565: {
		struct cheriabi_fhlink_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fhp; /* struct fhandle * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->to; /* const char * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi_fhlinkat */
	case 566: {
		struct cheriabi_fhlinkat_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fhp; /* struct fhandle * __capability */
		iarg[1] = p->tofd; /* int */
		uarg[2] = (__cheri_addr intptr_t) p->to; /* const char * __capability */
		*n_args = 3;
		break;
	}
	/* cheriabi_fhreadlink */
	case 567: {
		struct cheriabi_fhreadlink_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->fhp; /* struct fhandle * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->buf; /* char * __capability */
		uarg[2] = p->bufsize; /* size_t */
		*n_args = 3;
		break;
	}
	/* cheriabi_funlinkat */
	case 568: {
		struct cheriabi_funlinkat_args *p = params;
		iarg[0] = p->dfd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[2] = p->fd; /* int */
		iarg[3] = p->flag; /* int */
		*n_args = 4;
		break;
	}
	/* cheriabi_copy_file_range */
	case 569: {
		struct cheriabi_copy_file_range_args *p = params;
		iarg[0] = p->infd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->inoffp; /* off_t * __capability */
		iarg[2] = p->outfd; /* int */
		uarg[3] = (__cheri_addr intptr_t) p->outoffp; /* off_t * __capability */
		uarg[4] = p->len; /* size_t */
		uarg[5] = p->flags; /* unsigned int */
		*n_args = 6;
		break;
	}
	/* cheriabi___sysctlbyname */
	case 570: {
		struct cheriabi___sysctlbyname_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		uarg[1] = p->namelen; /* size_t */
		uarg[2] = (__cheri_addr intptr_t) p->old; /* void * __capability */
		uarg[3] = (__cheri_addr intptr_t) p->oldlenp; /* size_t * __capability */
		uarg[4] = (__cheri_addr intptr_t) p->new; /* void * __capability */
		uarg[5] = p->newlen; /* size_t */
		*n_args = 6;
		break;
	}
	/* cheriabi_shm_open2 */
	case 571: {
		struct cheriabi_shm_open2_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		iarg[1] = p->flags; /* int */
		iarg[2] = p->mode; /* mode_t */
		iarg[3] = p->shmflags; /* int */
		uarg[4] = (__cheri_addr intptr_t) p->name; /* const char * __capability */
		*n_args = 5;
		break;
	}
	/* cheriabi_shm_rename */
	case 572: {
		struct cheriabi_shm_rename_args *p = params;
		uarg[0] = (__cheri_addr intptr_t) p->path_from; /* const char * __capability */
		uarg[1] = (__cheri_addr intptr_t) p->path_to; /* const char * __capability */
		iarg[2] = p->flags; /* int */
		*n_args = 3;
		break;
	}
	/* cheriabi_sigfastblock */
	case 573: {
		struct cheriabi_sigfastblock_args *p = params;
		iarg[0] = p->cmd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->ptr; /* uint32_t * __capability */
		*n_args = 2;
		break;
	}
	/* cheriabi___realpathat */
	case 574: {
		struct cheriabi___realpathat_args *p = params;
		iarg[0] = p->fd; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
		uarg[2] = (__cheri_addr intptr_t) p->buf; /* char * __capability */
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
	/* cheriabi_rpctls_syscall */
	case 576: {
		struct cheriabi_rpctls_syscall_args *p = params;
		iarg[0] = p->op; /* int */
		uarg[1] = (__cheri_addr intptr_t) p->path; /* const char * __capability */
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
	/* cheriabi_read */
	case 3:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_write */
	case 4:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_open */
	case 5:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_wait4 */
	case 7:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland int * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland struct rusage * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_link */
	case 9:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_unlink */
	case 10:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_chdir */
	case 12:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_chmod */
	case 15:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_chown */
	case 16:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* getpid */
	case 20:
		break;
	/* cheriabi_mount */
	case 21:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_unmount */
	case 22:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_ptrace */
	case 26:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "pid_t";
			break;
		case 2:
			p = "userland char * __capability";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_recvmsg */
	case 27:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct msghdr_c * __capability";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sendmsg */
	case 28:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct msghdr_c * __capability";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_recvfrom */
	case 29:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland struct sockaddr * __capability";
			break;
		case 5:
			p = "userland __socklen_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_accept */
	case 30:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sockaddr * __capability";
			break;
		case 2:
			p = "userland __socklen_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getpeername */
	case 31:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sockaddr * __capability";
			break;
		case 2:
			p = "userland __socklen_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getsockname */
	case 32:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sockaddr * __capability";
			break;
		case 2:
			p = "userland __socklen_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_access */
	case 33:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_chflags */
	case 34:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_profil */
	case 44:
		switch(ndx) {
		case 0:
			p = "userland char * __capability";
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
	/* cheriabi_ktrace */
	case 45:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_getlogin */
	case 49:
		switch(ndx) {
		case 0:
			p = "userland char * __capability";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setlogin */
	case 50:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_acct */
	case 51:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigaltstack */
	case 53:
		switch(ndx) {
		case 0:
			p = "userland const struct sigaltstack_c * __capability";
			break;
		case 1:
			p = "userland struct sigaltstack_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ioctl */
	case 54:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "u_long";
			break;
		case 2:
			p = "userland char * __capability";
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
	/* cheriabi_revoke */
	case 56:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_symlink */
	case 57:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_readlink */
	case 58:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland char * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_execve */
	case 59:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland char * __capability * __capability";
			break;
		case 2:
			p = "userland char * __capability * __capability";
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
	/* cheriabi_chroot */
	case 61:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_msync */
	case 65:
		switch(ndx) {
		case 0:
			p = "userland void * __capability";
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
	/* cheriabi_munmap */
	case 73:
		switch(ndx) {
		case 0:
			p = "userland void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_mprotect */
	case 74:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
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
	/* cheriabi_madvise */
	case 75:
		switch(ndx) {
		case 0:
			p = "userland void * __capability";
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
	/* cheriabi_mincore */
	case 78:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getgroups */
	case 79:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "userland gid_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setgroups */
	case 80:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "userland const gid_t * __capability";
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
	/* cheriabi_setitimer */
	case 83:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct itimerval * __capability";
			break;
		case 2:
			p = "userland struct itimerval * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_swapon */
	case 85:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getitimer */
	case 86:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct itimerval * __capability";
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
	/* cheriabi_fcntl */
	case 92:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "intcap_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_select */
	case 93:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland fd_set * __capability";
			break;
		case 2:
			p = "userland fd_set * __capability";
			break;
		case 3:
			p = "userland fd_set * __capability";
			break;
		case 4:
			p = "userland struct timeval * __capability";
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
	/* cheriabi_connect */
	case 98:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct sockaddr * __capability";
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
	/* cheriabi_bind */
	case 104:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct sockaddr * __capability";
			break;
		case 2:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setsockopt */
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
			p = "userland const void * __capability";
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
	/* cheriabi_gettimeofday */
	case 116:
		switch(ndx) {
		case 0:
			p = "userland struct timeval * __capability";
			break;
		case 1:
			p = "userland struct timezone * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getrusage */
	case 117:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct rusage * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getsockopt */
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
			p = "userland void * __capability";
			break;
		case 4:
			p = "userland __socklen_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_readv */
	case 120:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec_c * __capability";
			break;
		case 2:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_writev */
	case 121:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec_c * __capability";
			break;
		case 2:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_settimeofday */
	case 122:
		switch(ndx) {
		case 0:
			p = "userland const struct timeval * __capability";
			break;
		case 1:
			p = "userland const struct timezone * __capability";
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
	/* cheriabi_rename */
	case 128:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_mkfifo */
	case 132:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sendto */
	case 133:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland const struct sockaddr * __capability";
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
	/* cheriabi_socketpair */
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
			p = "userland int * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_mkdir */
	case 136:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_rmdir */
	case 137:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_utimes */
	case 138:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland const struct timeval * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_adjtime */
	case 140:
		switch(ndx) {
		case 0:
			p = "userland const struct timeval * __capability";
			break;
		case 1:
			p = "userland struct timeval * __capability";
			break;
		default:
			break;
		};
		break;
	/* setsid */
	case 147:
		break;
	/* cheriabi_quotactl */
	case 148:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_nlm_syscall */
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
			p = "userland char * __capability * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_nfssvc */
	case 155:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_lgetfh */
	case 160:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland struct fhandle * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getfh */
	case 161:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland struct fhandle * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sysarch */
	case 165:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_rtprio */
	case 166:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "pid_t";
			break;
		case 2:
			p = "userland struct rtprio * __capability";
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
	/* cheriabi_ntp_adjtime */
	case 176:
		switch(ndx) {
		case 0:
			p = "userland struct timex * __capability";
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
	/* cheriabi_pathconf */
	case 191:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_getrlimit */
	case 194:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "userland struct rlimit * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setrlimit */
	case 195:
		switch(ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "userland struct rlimit * __capability";
			break;
		default:
			break;
		};
		break;
	/* nosys */
	case 198:
		break;
	/* cheriabi___sysctl */
	case 202:
		switch(ndx) {
		case 0:
			p = "userland int * __capability";
			break;
		case 1:
			p = "u_int";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "userland size_t * __capability";
			break;
		case 4:
			p = "userland const void * __capability";
			break;
		case 5:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_mlock */
	case 203:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_munlock */
	case 204:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_undelete */
	case 205:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_futimes */
	case 206:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct timeval * __capability";
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
	/* cheriabi_poll */
	case 209:
		switch(ndx) {
		case 0:
			p = "userland struct pollfd * __capability";
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
	/* cheriabi_semop */
	case 222:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sembuf * __capability";
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
	/* cheriabi_msgsnd */
	case 226:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void * __capability";
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
	/* cheriabi_msgrcv */
	case 227:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void * __capability";
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
	/* cheriabi_shmat */
	case 228:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void * __capability";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_shmdt */
	case 230:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
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
	/* cheriabi_clock_gettime */
	case 232:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_clock_settime */
	case 233:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland const struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_clock_getres */
	case 234:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ktimer_create */
	case 235:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct sigevent_c * __capability";
			break;
		case 2:
			p = "userland int * __capability";
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
	/* cheriabi_ktimer_settime */
	case 237:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct itimerspec * __capability";
			break;
		case 3:
			p = "userland struct itimerspec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ktimer_gettime */
	case 238:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct itimerspec * __capability";
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
	/* cheriabi_nanosleep */
	case 240:
		switch(ndx) {
		case 0:
			p = "userland const struct timespec * __capability";
			break;
		case 1:
			p = "userland struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ffclock_getcounter */
	case 241:
		switch(ndx) {
		case 0:
			p = "userland ffcounter * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ffclock_setestimate */
	case 242:
		switch(ndx) {
		case 0:
			p = "userland struct ffclock_estimate * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ffclock_getestimate */
	case 243:
		switch(ndx) {
		case 0:
			p = "userland struct ffclock_estimate * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_clock_nanosleep */
	case 244:
		switch(ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct timespec * __capability";
			break;
		case 3:
			p = "userland struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_clock_getcpuclockid2 */
	case 247:
		switch(ndx) {
		case 0:
			p = "id_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland clockid_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ntp_gettime */
	case 248:
		switch(ndx) {
		case 0:
			p = "userland struct ntptimeval * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_minherit */
	case 250:
		switch(ndx) {
		case 0:
			p = "userland void * __capability";
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
	/* cheriabi_lchown */
	case 254:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_aio_read */
	case 255:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_aio_write */
	case 256:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_lio_listio */
	case 257:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct aiocb_c * __capability const * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland struct sigevent_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kbounce */
	case 258:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "userland void * __capability";
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
	/* cheriabi_flag_captured */
	case 259:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_lchmod */
	case 274:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_lutimes */
	case 276:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland const struct timeval * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_preadv */
	case 289:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec_c * __capability";
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
	/* cheriabi_pwritev */
	case 290:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec_c * __capability";
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
	/* cheriabi_fhopen */
	case 298:
		switch(ndx) {
		case 0:
			p = "userland const struct fhandle * __capability";
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
	/* cheriabi_modstat */
	case 301:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct module_stat * __capability";
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
	/* cheriabi_modfind */
	case 303:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kldload */
	case 304:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_kldfind */
	case 306:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_kldstat */
	case 308:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct kld_file_stat_c * __capability";
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
	/* cheriabi_aio_return */
	case 314:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_aio_suspend */
	case 315:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb_c * __capability const * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_aio_cancel */
	case 316:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct aiocb_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_aio_error */
	case 317:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb_c * __capability";
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
	/* cheriabi___getcwd */
	case 326:
		switch(ndx) {
		case 0:
			p = "userland char * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sched_setparam */
	case 327:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "userland const struct sched_param * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sched_getparam */
	case 328:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "userland struct sched_param * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sched_setscheduler */
	case 329:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct sched_param * __capability";
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
	/* cheriabi_sched_rr_get_interval */
	case 334:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "userland struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_utrace */
	case 335:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kldsym */
	case 337:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_jail */
	case 338:
		switch(ndx) {
		case 0:
			p = "userland struct jail_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_nnpfs_syscall */
	case 339:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		case 4:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigprocmask */
	case 340:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const sigset_t * __capability";
			break;
		case 2:
			p = "userland sigset_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigsuspend */
	case 341:
		switch(ndx) {
		case 0:
			p = "userland const sigset_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigpending */
	case 343:
		switch(ndx) {
		case 0:
			p = "userland sigset_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigtimedwait */
	case 345:
		switch(ndx) {
		case 0:
			p = "userland const sigset_t * __capability";
			break;
		case 1:
			p = "userland struct siginfo_c * __capability";
			break;
		case 2:
			p = "userland const struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigwaitinfo */
	case 346:
		switch(ndx) {
		case 0:
			p = "userland const sigset_t * __capability";
			break;
		case 1:
			p = "userland struct siginfo_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_get_file */
	case 347:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_set_file */
	case 348:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_get_fd */
	case 349:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_set_fd */
	case 350:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_delete_file */
	case 351:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi___acl_aclcheck_file */
	case 353:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_aclcheck_fd */
	case 354:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattrctl */
	case 355:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_set_file */
	case 356:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_get_file */
	case 357:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_delete_file */
	case 358:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_aio_waitcomplete */
	case 359:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb_c * __capability * __capability";
			break;
		case 1:
			p = "userland struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getresuid */
	case 360:
		switch(ndx) {
		case 0:
			p = "userland uid_t * __capability";
			break;
		case 1:
			p = "userland uid_t * __capability";
			break;
		case 2:
			p = "userland uid_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getresgid */
	case 361:
		switch(ndx) {
		case 0:
			p = "userland gid_t * __capability";
			break;
		case 1:
			p = "userland gid_t * __capability";
			break;
		case 2:
			p = "userland gid_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* kqueue */
	case 362:
		break;
	/* cheriabi_extattr_set_fd */
	case 371:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_get_fd */
	case 372:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_delete_fd */
	case 373:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
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
	/* cheriabi_eaccess */
	case 376:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_nmount */
	case 378:
		switch(ndx) {
		case 0:
			p = "userland struct iovec_c * __capability";
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
	/* cheriabi___mac_get_proc */
	case 384:
		switch(ndx) {
		case 0:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___mac_set_proc */
	case 385:
		switch(ndx) {
		case 0:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___mac_get_fd */
	case 386:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___mac_get_file */
	case 387:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___mac_set_fd */
	case 388:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___mac_set_file */
	case 389:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kenv */
	case 390:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "userland char * __capability";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_lchflags */
	case 391:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "u_long";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_uuidgen */
	case 392:
		switch(ndx) {
		case 0:
			p = "userland struct uuid * __capability";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sendfile */
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
			p = "userland struct sf_hdtr_c * __capability";
			break;
		case 5:
			p = "userland off_t * __capability";
			break;
		case 6:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_mac_syscall */
	case 394:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void * __capability";
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
	/* cheriabi_ksem_init */
	case 404:
		switch(ndx) {
		case 0:
			p = "userland semid_t * __capability";
			break;
		case 1:
			p = "unsigned int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ksem_open */
	case 405:
		switch(ndx) {
		case 0:
			p = "userland semid_t * __capability";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_ksem_unlink */
	case 406:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ksem_getvalue */
	case 407:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		case 1:
			p = "userland int * __capability";
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
	/* cheriabi___mac_get_pid */
	case 409:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___mac_get_link */
	case 410:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___mac_set_link */
	case 411:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_set_link */
	case 412:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_get_link */
	case 413:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		case 4:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_delete_link */
	case 414:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___mac_execve */
	case 415:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland char * __capability * __capability";
			break;
		case 2:
			p = "userland char * __capability * __capability";
			break;
		case 3:
			p = "userland struct mac_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigaction */
	case 416:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct sigaction_c * __capability";
			break;
		case 2:
			p = "userland struct sigaction_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigreturn */
	case 417:
		switch(ndx) {
		case 0:
			p = "userland const struct __ucontext_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getcontext */
	case 421:
		switch(ndx) {
		case 0:
			p = "userland struct __ucontext_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setcontext */
	case 422:
		switch(ndx) {
		case 0:
			p = "userland const struct __ucontext_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_swapcontext */
	case 423:
		switch(ndx) {
		case 0:
			p = "userland struct __ucontext_c * __capability";
			break;
		case 1:
			p = "userland const struct __ucontext_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_swapoff */
	case 424:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_get_link */
	case 425:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_set_link */
	case 426:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_delete_link */
	case 427:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "acl_type_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___acl_aclcheck_link */
	case 428:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "acl_type_t";
			break;
		case 2:
			p = "userland struct acl * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigwait */
	case 429:
		switch(ndx) {
		case 0:
			p = "userland const sigset_t * __capability";
			break;
		case 1:
			p = "userland int * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_thr_create */
	case 430:
		switch(ndx) {
		case 0:
			p = "userland struct __ucontext_c * __capability";
			break;
		case 1:
			p = "userland long * __capability";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_thr_exit */
	case 431:
		switch(ndx) {
		case 0:
			p = "userland long * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_thr_self */
	case 432:
		switch(ndx) {
		case 0:
			p = "userland long * __capability";
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
	/* cheriabi_extattr_list_fd */
	case 437:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_list_file */
	case 438:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_extattr_list_link */
	case 439:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ksem_timedwait */
	case 441:
		switch(ndx) {
		case 0:
			p = "semid_t";
			break;
		case 1:
			p = "userland const struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_thr_suspend */
	case 442:
		switch(ndx) {
		case 0:
			p = "userland const struct timespec * __capability";
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
	/* cheriabi_audit */
	case 445:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_auditon */
	case 446:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void * __capability";
			break;
		case 2:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getauid */
	case 447:
		switch(ndx) {
		case 0:
			p = "userland uid_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setauid */
	case 448:
		switch(ndx) {
		case 0:
			p = "userland uid_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getaudit */
	case 449:
		switch(ndx) {
		case 0:
			p = "userland struct auditinfo * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setaudit */
	case 450:
		switch(ndx) {
		case 0:
			p = "userland struct auditinfo * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getaudit_addr */
	case 451:
		switch(ndx) {
		case 0:
			p = "userland struct auditinfo_addr * __capability";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setaudit_addr */
	case 452:
		switch(ndx) {
		case 0:
			p = "userland struct auditinfo_addr * __capability";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_auditctl */
	case 453:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi__umtx_op */
	case 454:
		switch(ndx) {
		case 0:
			p = "userland void * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "u_long";
			break;
		case 3:
			p = "userland void * __capability";
			break;
		case 4:
			p = "userland void * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_thr_new */
	case 455:
		switch(ndx) {
		case 0:
			p = "userland struct thr_param_c * __capability";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigqueue */
	case 456:
		switch(ndx) {
		case 0:
			p = "pid_t";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kmq_open */
	case 457:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "mode_t";
			break;
		case 3:
			p = "userland const struct mq_attr * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kmq_setattr */
	case 458:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct mq_attr * __capability";
			break;
		case 2:
			p = "userland struct mq_attr * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kmq_timedreceive */
	case 459:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "userland unsigned * __capability";
			break;
		case 4:
			p = "userland const struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kmq_timedsend */
	case 460:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "unsigned";
			break;
		case 4:
			p = "userland const struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kmq_notify */
	case 461:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct sigevent_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_kmq_unlink */
	case 462:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_abort2 */
	case 463:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland void * __capability * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_thr_set_name */
	case 464:
		switch(ndx) {
		case 0:
			p = "long";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_aio_fsync */
	case 465:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct aiocb_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_rtprio_thread */
	case 466:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "lwpid_t";
			break;
		case 2:
			p = "userland struct rtprio * __capability";
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
	/* cheriabi_sctp_generic_sendmsg */
	case 472:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const struct sockaddr * __capability";
			break;
		case 4:
			p = "__socklen_t";
			break;
		case 5:
			p = "userland struct sctp_sndrcvinfo * __capability";
			break;
		case 6:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sctp_generic_sendmsg_iov */
	case 473:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec_c * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const struct sockaddr * __capability";
			break;
		case 4:
			p = "__socklen_t";
			break;
		case 5:
			p = "userland struct sctp_sndrcvinfo * __capability";
			break;
		case 6:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sctp_generic_recvmsg */
	case 474:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec_c * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland struct sockaddr * __capability";
			break;
		case 4:
			p = "userland __socklen_t * __capability";
			break;
		case 5:
			p = "userland struct sctp_sndrcvinfo * __capability";
			break;
		case 6:
			p = "userland int * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_pread */
	case 475:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland void * __capability";
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
	/* cheriabi_pwrite */
	case 476:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const void * __capability";
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
	/* cheriabi_mmap */
	case 477:
		switch(ndx) {
		case 0:
			p = "userland void * __capability";
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
	/* cheriabi_truncate */
	case 479:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
	/* cheriabi_shm_unlink */
	case 483:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_cpuset */
	case 484:
		switch(ndx) {
		case 0:
			p = "userland cpusetid_t * __capability";
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
	/* cheriabi_cpuset_getid */
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
			p = "userland cpusetid_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_cpuset_getaffinity */
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
			p = "userland cpuset_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_cpuset_setaffinity */
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
			p = "userland const cpuset_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_faccessat */
	case 489:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_fchmodat */
	case 490:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_fchownat */
	case 491:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_fexecve */
	case 492:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char * __capability * __capability";
			break;
		case 2:
			p = "userland char * __capability * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_futimesat */
	case 494:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "userland const struct timeval * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_linkat */
	case 495:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const char * __capability";
			break;
		case 4:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_mkdirat */
	case 496:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_mkfifoat */
	case 497:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "mode_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_openat */
	case 499:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_readlinkat */
	case 500:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "userland char * __capability";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_renameat */
	case 501:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_symlinkat */
	case 502:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_unlinkat */
	case 503:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_gssd_syscall */
	case 505:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_jail_get */
	case 506:
		switch(ndx) {
		case 0:
			p = "userland struct iovec_c * __capability";
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
	/* cheriabi_jail_set */
	case 507:
		switch(ndx) {
		case 0:
			p = "userland struct iovec_c * __capability";
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
	/* cheriabi___semctl */
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
			p = "userland union semun_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_msgctl */
	case 511:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland struct msqid_ds_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_shmctl */
	case 512:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland struct shmid_ds * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_lpathconf */
	case 513:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___cap_rights_get */
	case 515:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland cap_rights_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cap_enter */
	case 516:
		break;
	/* cheriabi_cap_getmode */
	case 517:
		switch(ndx) {
		case 0:
			p = "userland u_int * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_pdfork */
	case 518:
		switch(ndx) {
		case 0:
			p = "userland int * __capability";
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
	/* cheriabi_pdgetpid */
	case 520:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland pid_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_pselect */
	case 522:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland fd_set * __capability";
			break;
		case 2:
			p = "userland fd_set * __capability";
			break;
		case 3:
			p = "userland fd_set * __capability";
			break;
		case 4:
			p = "userland const struct timespec * __capability";
			break;
		case 5:
			p = "userland const sigset_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getloginclass */
	case 523:
		switch(ndx) {
		case 0:
			p = "userland char * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_setloginclass */
	case 524:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_rctl_get_racct */
	case 525:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_rctl_get_rules */
	case 526:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_rctl_get_limits */
	case 527:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_rctl_add_rule */
	case 528:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_rctl_remove_rule */
	case 529:
		switch(ndx) {
		case 0:
			p = "userland const void * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void * __capability";
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
	/* cheriabi_wait6 */
	case 532:
		switch(ndx) {
		case 0:
			p = "idtype_t";
			break;
		case 1:
			p = "id_t";
			break;
		case 2:
			p = "userland int * __capability";
			break;
		case 3:
			p = "int";
			break;
		case 4:
			p = "userland struct __wrusage * __capability";
			break;
		case 5:
			p = "userland struct siginfo_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_cap_rights_limit */
	case 533:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland cap_rights_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_cap_ioctls_limit */
	case 534:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const u_long * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_cap_ioctls_get */
	case 535:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland u_long * __capability";
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
	/* cheriabi_cap_fcntls_get */
	case 537:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland uint32_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_bindat */
	case 538:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct sockaddr * __capability";
			break;
		case 3:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_connectat */
	case 539:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const struct sockaddr * __capability";
			break;
		case 3:
			p = "__socklen_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_chflagsat */
	case 540:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_accept4 */
	case 541:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct sockaddr * __capability";
			break;
		case 2:
			p = "userland __socklen_t * __capability";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_pipe2 */
	case 542:
		switch(ndx) {
		case 0:
			p = "userland int * __capability";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_aio_mlock */
	case 543:
		switch(ndx) {
		case 0:
			p = "userland struct aiocb_c * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_procctl */
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
			p = "userland void * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_ppoll */
	case 545:
		switch(ndx) {
		case 0:
			p = "userland struct pollfd * __capability";
			break;
		case 1:
			p = "u_int";
			break;
		case 2:
			p = "userland const struct timespec * __capability";
			break;
		case 3:
			p = "userland const sigset_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_futimens */
	case 546:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_utimensat */
	case 547:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "userland const struct timespec * __capability";
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
	/* cheriabi_fstat */
	case 551:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct stat * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_fstatat */
	case 552:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "userland struct stat * __capability";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_fhstat */
	case 553:
		switch(ndx) {
		case 0:
			p = "userland const struct fhandle * __capability";
			break;
		case 1:
			p = "userland struct stat * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getdirentries */
	case 554:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		case 3:
			p = "userland off_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_statfs */
	case 555:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland struct statfs * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_fstatfs */
	case 556:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct statfs * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getfsstat */
	case 557:
		switch(ndx) {
		case 0:
			p = "userland struct statfs * __capability";
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
	/* cheriabi_fhstatfs */
	case 558:
		switch(ndx) {
		case 0:
			p = "userland const struct fhandle * __capability";
			break;
		case 1:
			p = "userland struct statfs * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_mknodat */
	case 559:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_kevent */
	case 560:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const struct kevent_c * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland struct kevent_c * __capability";
			break;
		case 4:
			p = "int";
			break;
		case 5:
			p = "userland const struct timespec * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_cpuset_getdomain */
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
			p = "userland domainset_t * __capability";
			break;
		case 5:
			p = "userland int * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_cpuset_setdomain */
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
			p = "userland domainset_t * __capability";
			break;
		case 5:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_getrandom */
	case 563:
		switch(ndx) {
		case 0:
			p = "userland void * __capability";
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
	/* cheriabi_getfhat */
	case 564:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char * __capability";
			break;
		case 2:
			p = "userland struct fhandle * __capability";
			break;
		case 3:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_fhlink */
	case 565:
		switch(ndx) {
		case 0:
			p = "userland struct fhandle * __capability";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_fhlinkat */
	case 566:
		switch(ndx) {
		case 0:
			p = "userland struct fhandle * __capability";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_fhreadlink */
	case 567:
		switch(ndx) {
		case 0:
			p = "userland struct fhandle * __capability";
			break;
		case 1:
			p = "userland char * __capability";
			break;
		case 2:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_funlinkat */
	case 568:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_copy_file_range */
	case 569:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland off_t * __capability";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland off_t * __capability";
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
	/* cheriabi___sysctlbyname */
	case 570:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "size_t";
			break;
		case 2:
			p = "userland void * __capability";
			break;
		case 3:
			p = "userland size_t * __capability";
			break;
		case 4:
			p = "userland void * __capability";
			break;
		case 5:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_shm_open2 */
	case 571:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
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
			p = "userland const char * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_shm_rename */
	case 572:
		switch(ndx) {
		case 0:
			p = "userland const char * __capability";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* cheriabi_sigfastblock */
	case 573:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland uint32_t * __capability";
			break;
		default:
			break;
		};
		break;
	/* cheriabi___realpathat */
	case 574:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
			break;
		case 2:
			p = "userland char * __capability";
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
	/* cheriabi_rpctls_syscall */
	case 576:
		switch(ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland const char * __capability";
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
	/* cheriabi_read */
	case 3:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_write */
	case 4:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_open */
	case 5:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* close */
	case 6:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_wait4 */
	case 7:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_link */
	case 9:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_unlink */
	case 10:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_chdir */
	case 12:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fchdir */
	case 13:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_chmod */
	case 15:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_chown */
	case 16:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getpid */
	case 20:
	/* cheriabi_mount */
	case 21:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_unmount */
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
	/* cheriabi_ptrace */
	case 26:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_recvmsg */
	case 27:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_sendmsg */
	case 28:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_recvfrom */
	case 29:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_accept */
	case 30:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getpeername */
	case 31:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getsockname */
	case 32:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_access */
	case 33:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_chflags */
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
	/* cheriabi_profil */
	case 44:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ktrace */
	case 45:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getgid */
	case 47:
	/* cheriabi_getlogin */
	case 49:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setlogin */
	case 50:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_acct */
	case 51:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigaltstack */
	case 53:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ioctl */
	case 54:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* reboot */
	case 55:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_revoke */
	case 56:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_symlink */
	case 57:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_readlink */
	case 58:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_execve */
	case 59:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* umask */
	case 60:
		if (ndx == 0 || ndx == 1)
			p = "mode_t";
		break;
	/* cheriabi_chroot */
	case 61:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_msync */
	case 65:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* vfork */
	case 66:
	/* cheriabi_munmap */
	case 73:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mprotect */
	case 74:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_madvise */
	case 75:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mincore */
	case 78:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getgroups */
	case 79:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setgroups */
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
	/* cheriabi_setitimer */
	case 83:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_swapon */
	case 85:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getitimer */
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
	/* cheriabi_fcntl */
	case 92:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_select */
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
	/* cheriabi_connect */
	case 98:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getpriority */
	case 100:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_bind */
	case 104:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setsockopt */
	case 105:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* listen */
	case 106:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_gettimeofday */
	case 116:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getrusage */
	case 117:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getsockopt */
	case 118:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_readv */
	case 120:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_writev */
	case 121:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_settimeofday */
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
	/* cheriabi_rename */
	case 128:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* flock */
	case 131:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mkfifo */
	case 132:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sendto */
	case 133:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* shutdown */
	case 134:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_socketpair */
	case 135:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mkdir */
	case 136:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rmdir */
	case 137:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_utimes */
	case 138:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_adjtime */
	case 140:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setsid */
	case 147:
	/* cheriabi_quotactl */
	case 148:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_nlm_syscall */
	case 154:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_nfssvc */
	case 155:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_lgetfh */
	case 160:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getfh */
	case 161:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sysarch */
	case 165:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rtprio */
	case 166:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setfib */
	case 175:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ntp_adjtime */
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
	/* cheriabi_pathconf */
	case 191:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fpathconf */
	case 192:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getrlimit */
	case 194:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setrlimit */
	case 195:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* nosys */
	case 198:
	/* cheriabi___sysctl */
	case 202:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mlock */
	case 203:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_munlock */
	case 204:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_undelete */
	case 205:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_futimes */
	case 206:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getpgid */
	case 207:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_poll */
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
	/* cheriabi_semop */
	case 222:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* msgget */
	case 225:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_msgsnd */
	case 226:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_msgrcv */
	case 227:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_shmat */
	case 228:
		if (ndx == 0 || ndx == 1)
			p = "void *";
		break;
	/* cheriabi_shmdt */
	case 230:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* shmget */
	case 231:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_clock_gettime */
	case 232:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_clock_settime */
	case 233:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_clock_getres */
	case 234:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ktimer_create */
	case 235:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ktimer_delete */
	case 236:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ktimer_settime */
	case 237:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ktimer_gettime */
	case 238:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ktimer_getoverrun */
	case 239:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_nanosleep */
	case 240:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ffclock_getcounter */
	case 241:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ffclock_setestimate */
	case 242:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ffclock_getestimate */
	case 243:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_clock_nanosleep */
	case 244:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_clock_getcpuclockid2 */
	case 247:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ntp_gettime */
	case 248:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_minherit */
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
	/* cheriabi_lchown */
	case 254:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_aio_read */
	case 255:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_aio_write */
	case 256:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_lio_listio */
	case 257:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kbounce */
	case 258:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_flag_captured */
	case 259:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_lchmod */
	case 274:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_lutimes */
	case 276:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_preadv */
	case 289:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_pwritev */
	case 290:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_fhopen */
	case 298:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* modnext */
	case 300:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_modstat */
	case 301:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* modfnext */
	case 302:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_modfind */
	case 303:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kldload */
	case 304:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* kldunload */
	case 305:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kldfind */
	case 306:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* kldnext */
	case 307:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kldstat */
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
	/* cheriabi_aio_return */
	case 314:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_aio_suspend */
	case 315:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_aio_cancel */
	case 316:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_aio_error */
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
	/* cheriabi___getcwd */
	case 326:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sched_setparam */
	case 327:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sched_getparam */
	case 328:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sched_setscheduler */
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
	/* cheriabi_sched_rr_get_interval */
	case 334:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_utrace */
	case 335:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kldsym */
	case 337:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_jail */
	case 338:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_nnpfs_syscall */
	case 339:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigprocmask */
	case 340:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigsuspend */
	case 341:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigpending */
	case 343:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigtimedwait */
	case 345:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigwaitinfo */
	case 346:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_get_file */
	case 347:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_set_file */
	case 348:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_get_fd */
	case 349:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_set_fd */
	case 350:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_delete_file */
	case 351:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* __acl_delete_fd */
	case 352:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_aclcheck_file */
	case 353:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_aclcheck_fd */
	case 354:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_extattrctl */
	case 355:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_extattr_set_file */
	case 356:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_extattr_get_file */
	case 357:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_extattr_delete_file */
	case 358:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_aio_waitcomplete */
	case 359:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_getresuid */
	case 360:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getresgid */
	case 361:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* kqueue */
	case 362:
	/* cheriabi_extattr_set_fd */
	case 371:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_extattr_get_fd */
	case 372:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_extattr_delete_fd */
	case 373:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* __setugid */
	case 374:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_eaccess */
	case 376:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* afs3_syscall */
	case 377:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_nmount */
	case 378:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_get_proc */
	case 384:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_set_proc */
	case 385:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_get_fd */
	case 386:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_get_file */
	case 387:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_set_fd */
	case 388:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_set_file */
	case 389:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kenv */
	case 390:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_lchflags */
	case 391:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_uuidgen */
	case 392:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sendfile */
	case 393:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mac_syscall */
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
	/* cheriabi_ksem_init */
	case 404:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ksem_open */
	case 405:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ksem_unlink */
	case 406:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ksem_getvalue */
	case 407:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* ksem_destroy */
	case 408:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_get_pid */
	case 409:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_get_link */
	case 410:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_set_link */
	case 411:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_extattr_set_link */
	case 412:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_extattr_get_link */
	case 413:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_extattr_delete_link */
	case 414:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___mac_execve */
	case 415:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigaction */
	case 416:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigreturn */
	case 417:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getcontext */
	case 421:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setcontext */
	case 422:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_swapcontext */
	case 423:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_swapoff */
	case 424:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_get_link */
	case 425:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_set_link */
	case 426:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_delete_link */
	case 427:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___acl_aclcheck_link */
	case 428:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigwait */
	case 429:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_thr_create */
	case 430:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_thr_exit */
	case 431:
		if (ndx == 0 || ndx == 1)
			p = "void";
		break;
	/* cheriabi_thr_self */
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
	/* cheriabi_extattr_list_fd */
	case 437:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_extattr_list_file */
	case 438:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_extattr_list_link */
	case 439:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_ksem_timedwait */
	case 441:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_thr_suspend */
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
	/* cheriabi_audit */
	case 445:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_auditon */
	case 446:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getauid */
	case 447:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setauid */
	case 448:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getaudit */
	case 449:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setaudit */
	case 450:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getaudit_addr */
	case 451:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setaudit_addr */
	case 452:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_auditctl */
	case 453:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi__umtx_op */
	case 454:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_thr_new */
	case 455:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigqueue */
	case 456:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kmq_open */
	case 457:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kmq_setattr */
	case 458:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kmq_timedreceive */
	case 459:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kmq_timedsend */
	case 460:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kmq_notify */
	case 461:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kmq_unlink */
	case 462:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_abort2 */
	case 463:
		if (ndx == 0 || ndx == 1)
			p = "void";
		break;
	/* cheriabi_thr_set_name */
	case 464:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_aio_fsync */
	case 465:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rtprio_thread */
	case 466:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sctp_peeloff */
	case 471:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sctp_generic_sendmsg */
	case 472:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sctp_generic_sendmsg_iov */
	case 473:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sctp_generic_recvmsg */
	case 474:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_pread */
	case 475:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_pwrite */
	case 476:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_mmap */
	case 477:
		if (ndx == 0 || ndx == 1)
			p = "void *";
		break;
	/* lseek */
	case 478:
		if (ndx == 0 || ndx == 1)
			p = "off_t";
		break;
	/* cheriabi_truncate */
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
	/* cheriabi_shm_unlink */
	case 483:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cpuset */
	case 484:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cpuset_setid */
	case 485:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cpuset_getid */
	case 486:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cpuset_getaffinity */
	case 487:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cpuset_setaffinity */
	case 488:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_faccessat */
	case 489:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fchmodat */
	case 490:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fchownat */
	case 491:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fexecve */
	case 492:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_futimesat */
	case 494:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_linkat */
	case 495:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mkdirat */
	case 496:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mkfifoat */
	case 497:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_openat */
	case 499:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_readlinkat */
	case 500:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_renameat */
	case 501:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_symlinkat */
	case 502:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_unlinkat */
	case 503:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* posix_openpt */
	case 504:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_gssd_syscall */
	case 505:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_jail_get */
	case 506:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_jail_set */
	case 507:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* jail_remove */
	case 508:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___semctl */
	case 510:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_msgctl */
	case 511:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_shmctl */
	case 512:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_lpathconf */
	case 513:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___cap_rights_get */
	case 515:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cap_enter */
	case 516:
	/* cheriabi_cap_getmode */
	case 517:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_pdfork */
	case 518:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* pdkill */
	case 519:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_pdgetpid */
	case 520:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_pselect */
	case 522:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getloginclass */
	case 523:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_setloginclass */
	case 524:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rctl_get_racct */
	case 525:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rctl_get_rules */
	case 526:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rctl_get_limits */
	case 527:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rctl_add_rule */
	case 528:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rctl_remove_rule */
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
	/* cheriabi_wait6 */
	case 532:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cap_rights_limit */
	case 533:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cap_ioctls_limit */
	case 534:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cap_ioctls_get */
	case 535:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cap_fcntls_limit */
	case 536:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cap_fcntls_get */
	case 537:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_bindat */
	case 538:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_connectat */
	case 539:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_chflagsat */
	case 540:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_accept4 */
	case 541:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_pipe2 */
	case 542:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_aio_mlock */
	case 543:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_procctl */
	case 544:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_ppoll */
	case 545:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_futimens */
	case 546:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_utimensat */
	case 547:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fdatasync */
	case 550:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fstat */
	case 551:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fstatat */
	case 552:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fhstat */
	case 553:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getdirentries */
	case 554:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi_statfs */
	case 555:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fstatfs */
	case 556:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getfsstat */
	case 557:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fhstatfs */
	case 558:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_mknodat */
	case 559:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_kevent */
	case 560:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cpuset_getdomain */
	case 561:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_cpuset_setdomain */
	case 562:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getrandom */
	case 563:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_getfhat */
	case 564:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fhlink */
	case 565:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fhlinkat */
	case 566:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_fhreadlink */
	case 567:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_funlinkat */
	case 568:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_copy_file_range */
	case 569:
		if (ndx == 0 || ndx == 1)
			p = "ssize_t";
		break;
	/* cheriabi___sysctlbyname */
	case 570:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_shm_open2 */
	case 571:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_shm_rename */
	case 572:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_sigfastblock */
	case 573:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi___realpathat */
	case 574:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* close_range */
	case 575:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* cheriabi_rpctls_syscall */
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
