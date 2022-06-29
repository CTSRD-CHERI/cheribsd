/*
 * System call switch table.
 *
 * DO NOT EDIT-- this file is automatically @generated.
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <compat/freebsd64/freebsd64_proto.h>

#define AS(name) (sizeof(struct name) / sizeof(syscallarg_t))

#ifdef COMPAT_FREEBSD6
#define compat6(n, name) .sy_narg = n, .sy_call = (sy_call_t *)__CONCAT(freebsd6_, name)
#else
#define compat6(n, name) .sy_narg = 0, .sy_call = (sy_call_t *)nosys
#endif

#ifdef COMPAT_FREEBSD7
#define compat7(n, name) .sy_narg = n, .sy_call = (sy_call_t *)__CONCAT(freebsd7_, name)
#else
#define compat7(n, name) .sy_narg = 0, .sy_call = (sy_call_t *)nosys
#endif

#ifdef COMPAT_FREEBSD10
#define compat10(n, name) .sy_narg = n, .sy_call = (sy_call_t *)__CONCAT(freebsd10_, name)
#else
#define compat10(n, name) .sy_narg = 0, .sy_call = (sy_call_t *)nosys
#endif

#ifdef COMPAT_FREEBSD11
#define compat11(n, name) .sy_narg = n, .sy_call = (sy_call_t *)__CONCAT(freebsd11_, name)
#else
#define compat11(n, name) .sy_narg = 0, .sy_call = (sy_call_t *)nosys
#endif

#ifdef COMPAT_FREEBSD12
#define compat12(n, name) .sy_narg = n, .sy_call = (sy_call_t *)__CONCAT(freebsd12_, name)
#else
#define compat12(n, name) .sy_narg = 0, .sy_call = (sy_call_t *)nosys
#endif

#ifdef COMPAT_FREEBSD13
#define compat13(n, name) .sy_narg = n, .sy_call = (sy_call_t *)__CONCAT(freebsd13_, name)
#else
#define compat13(n, name) .sy_narg = 0, .sy_call = (sy_call_t *)nosys
#endif

/* The casts are bogus but will do for now. */
struct sysent freebsd64_sysent[] = {
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },		/* 0 = syscall */
	{ .sy_narg = AS(exit_args), .sy_call = (sy_call_t *)sys_exit, .sy_auevent = AUE_EXIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 1 = exit */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_fork, .sy_auevent = AUE_FORK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 2 = fork */
	{ .sy_narg = AS(freebsd64_read_args), .sy_call = (sy_call_t *)freebsd64_read, .sy_auevent = AUE_READ, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 3 = freebsd64_read */
	{ .sy_narg = AS(freebsd64_write_args), .sy_call = (sy_call_t *)freebsd64_write, .sy_auevent = AUE_WRITE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 4 = freebsd64_write */
	{ .sy_narg = AS(freebsd64_open_args), .sy_call = (sy_call_t *)freebsd64_open, .sy_auevent = AUE_OPEN_RWTC, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 5 = freebsd64_open */
	{ .sy_narg = AS(close_args), .sy_call = (sy_call_t *)sys_close, .sy_auevent = AUE_CLOSE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 6 = close */
	{ .sy_narg = AS(freebsd64_wait4_args), .sy_call = (sy_call_t *)freebsd64_wait4, .sy_auevent = AUE_WAIT4, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 7 = freebsd64_wait4 */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 8 = obsolete ocreat */
	{ .sy_narg = AS(freebsd64_link_args), .sy_call = (sy_call_t *)freebsd64_link, .sy_auevent = AUE_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 9 = freebsd64_link */
	{ .sy_narg = AS(freebsd64_unlink_args), .sy_call = (sy_call_t *)freebsd64_unlink, .sy_auevent = AUE_UNLINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 10 = freebsd64_unlink */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 11 = obsolete execv */
	{ .sy_narg = AS(freebsd64_chdir_args), .sy_call = (sy_call_t *)freebsd64_chdir, .sy_auevent = AUE_CHDIR, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 12 = freebsd64_chdir */
	{ .sy_narg = AS(fchdir_args), .sy_call = (sy_call_t *)sys_fchdir, .sy_auevent = AUE_FCHDIR, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 13 = fchdir */
	{ compat11(AS(freebsd11_freebsd64_mknod_args),freebsd64_mknod), .sy_auevent = AUE_MKNOD, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 14 = freebsd11 freebsd64_mknod */
	{ .sy_narg = AS(freebsd64_chmod_args), .sy_call = (sy_call_t *)freebsd64_chmod, .sy_auevent = AUE_CHMOD, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 15 = freebsd64_chmod */
	{ .sy_narg = AS(freebsd64_chown_args), .sy_call = (sy_call_t *)freebsd64_chown, .sy_auevent = AUE_CHOWN, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 16 = freebsd64_chown */
	{ .sy_narg = AS(freebsd64_break_args), .sy_call = (sy_call_t *)freebsd64_break, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 17 = freebsd64_break */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 18 = obsolete freebsd4_getfsstat */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 19 = obsolete olseek */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_getpid, .sy_auevent = AUE_GETPID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 20 = getpid */
	{ .sy_narg = AS(freebsd64_mount_args), .sy_call = (sy_call_t *)freebsd64_mount, .sy_auevent = AUE_MOUNT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 21 = freebsd64_mount */
	{ .sy_narg = AS(freebsd64_unmount_args), .sy_call = (sy_call_t *)freebsd64_unmount, .sy_auevent = AUE_UMOUNT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 22 = freebsd64_unmount */
	{ .sy_narg = AS(setuid_args), .sy_call = (sy_call_t *)sys_setuid, .sy_auevent = AUE_SETUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 23 = setuid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_getuid, .sy_auevent = AUE_GETUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 24 = getuid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_geteuid, .sy_auevent = AUE_GETEUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 25 = geteuid */
	{ .sy_narg = AS(freebsd64_ptrace_args), .sy_call = (sy_call_t *)freebsd64_ptrace, .sy_auevent = AUE_PTRACE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 26 = freebsd64_ptrace */
	{ .sy_narg = AS(freebsd64_recvmsg_args), .sy_call = (sy_call_t *)freebsd64_recvmsg, .sy_auevent = AUE_RECVMSG, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 27 = freebsd64_recvmsg */
	{ .sy_narg = AS(freebsd64_sendmsg_args), .sy_call = (sy_call_t *)freebsd64_sendmsg, .sy_auevent = AUE_SENDMSG, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 28 = freebsd64_sendmsg */
	{ .sy_narg = AS(freebsd64_recvfrom_args), .sy_call = (sy_call_t *)freebsd64_recvfrom, .sy_auevent = AUE_RECVFROM, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 29 = freebsd64_recvfrom */
	{ .sy_narg = AS(freebsd64_accept_args), .sy_call = (sy_call_t *)freebsd64_accept, .sy_auevent = AUE_ACCEPT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 30 = freebsd64_accept */
	{ .sy_narg = AS(freebsd64_getpeername_args), .sy_call = (sy_call_t *)freebsd64_getpeername, .sy_auevent = AUE_GETPEERNAME, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 31 = freebsd64_getpeername */
	{ .sy_narg = AS(freebsd64_getsockname_args), .sy_call = (sy_call_t *)freebsd64_getsockname, .sy_auevent = AUE_GETSOCKNAME, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 32 = freebsd64_getsockname */
	{ .sy_narg = AS(freebsd64_access_args), .sy_call = (sy_call_t *)freebsd64_access, .sy_auevent = AUE_ACCESS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 33 = freebsd64_access */
	{ .sy_narg = AS(freebsd64_chflags_args), .sy_call = (sy_call_t *)freebsd64_chflags, .sy_auevent = AUE_CHFLAGS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 34 = freebsd64_chflags */
	{ .sy_narg = AS(fchflags_args), .sy_call = (sy_call_t *)sys_fchflags, .sy_auevent = AUE_FCHFLAGS, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 35 = fchflags */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_sync, .sy_auevent = AUE_SYNC, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 36 = sync */
	{ .sy_narg = AS(kill_args), .sy_call = (sy_call_t *)sys_kill, .sy_auevent = AUE_KILL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 37 = kill */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 38 = obsolete ostat */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_getppid, .sy_auevent = AUE_GETPPID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 39 = getppid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 40 = obsolete olstat */
	{ .sy_narg = AS(dup_args), .sy_call = (sy_call_t *)sys_dup, .sy_auevent = AUE_DUP, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 41 = dup */
	{ compat10(0,pipe), .sy_auevent = AUE_PIPE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 42 = freebsd10 pipe */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_getegid, .sy_auevent = AUE_GETEGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 43 = getegid */
	{ .sy_narg = AS(freebsd64_profil_args), .sy_call = (sy_call_t *)freebsd64_profil, .sy_auevent = AUE_PROFILE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 44 = freebsd64_profil */
	{ .sy_narg = AS(freebsd64_ktrace_args), .sy_call = (sy_call_t *)freebsd64_ktrace, .sy_auevent = AUE_KTRACE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 45 = freebsd64_ktrace */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 46 = obsolete osigaction */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_getgid, .sy_auevent = AUE_GETGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 47 = getgid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 48 = obsolete osigprocmask */
	{ .sy_narg = AS(freebsd64_getlogin_args), .sy_call = (sy_call_t *)freebsd64_getlogin, .sy_auevent = AUE_GETLOGIN, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 49 = freebsd64_getlogin */
	{ .sy_narg = AS(freebsd64_setlogin_args), .sy_call = (sy_call_t *)freebsd64_setlogin, .sy_auevent = AUE_SETLOGIN, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 50 = freebsd64_setlogin */
	{ .sy_narg = AS(freebsd64_acct_args), .sy_call = (sy_call_t *)freebsd64_acct, .sy_auevent = AUE_ACCT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 51 = freebsd64_acct */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 52 = obsolete osigpending */
	{ .sy_narg = AS(freebsd64_sigaltstack_args), .sy_call = (sy_call_t *)freebsd64_sigaltstack, .sy_auevent = AUE_SIGALTSTACK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 53 = freebsd64_sigaltstack */
	{ .sy_narg = AS(freebsd64_ioctl_args), .sy_call = (sy_call_t *)freebsd64_ioctl, .sy_auevent = AUE_IOCTL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 54 = freebsd64_ioctl */
	{ .sy_narg = AS(reboot_args), .sy_call = (sy_call_t *)sys_reboot, .sy_auevent = AUE_REBOOT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 55 = reboot */
	{ .sy_narg = AS(freebsd64_revoke_args), .sy_call = (sy_call_t *)freebsd64_revoke, .sy_auevent = AUE_REVOKE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 56 = freebsd64_revoke */
	{ .sy_narg = AS(freebsd64_symlink_args), .sy_call = (sy_call_t *)freebsd64_symlink, .sy_auevent = AUE_SYMLINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 57 = freebsd64_symlink */
	{ .sy_narg = AS(freebsd64_readlink_args), .sy_call = (sy_call_t *)freebsd64_readlink, .sy_auevent = AUE_READLINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 58 = freebsd64_readlink */
	{ .sy_narg = AS(freebsd64_execve_args), .sy_call = (sy_call_t *)freebsd64_execve, .sy_auevent = AUE_EXECVE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 59 = freebsd64_execve */
	{ .sy_narg = AS(umask_args), .sy_call = (sy_call_t *)sys_umask, .sy_auevent = AUE_UMASK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 60 = umask */
	{ .sy_narg = AS(freebsd64_chroot_args), .sy_call = (sy_call_t *)freebsd64_chroot, .sy_auevent = AUE_CHROOT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 61 = freebsd64_chroot */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 62 = obsolete ofstat */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 63 = obsolete ogetkerninfo */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 64 = obsolete ogetpagesize */
	{ .sy_narg = AS(freebsd64_msync_args), .sy_call = (sy_call_t *)freebsd64_msync, .sy_auevent = AUE_MSYNC, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 65 = freebsd64_msync */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_vfork, .sy_auevent = AUE_VFORK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 66 = vfork */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 67 = obsolete vread */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 68 = obsolete vwrite */
	{ .sy_narg = AS(sbrk_args), .sy_call = (sy_call_t *)sys_sbrk, .sy_auevent = AUE_SBRK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 69 = sbrk */
	{ .sy_narg = AS(sstk_args), .sy_call = (sy_call_t *)sys_sstk, .sy_auevent = AUE_SSTK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 70 = sstk */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 71 = obsolete ommap */
	{ compat11(AS(freebsd11_vadvise_args),vadvise), .sy_auevent = AUE_O_VADVISE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 72 = freebsd11 vadvise */
	{ .sy_narg = AS(freebsd64_munmap_args), .sy_call = (sy_call_t *)freebsd64_munmap, .sy_auevent = AUE_MUNMAP, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 73 = freebsd64_munmap */
	{ .sy_narg = AS(freebsd64_mprotect_args), .sy_call = (sy_call_t *)freebsd64_mprotect, .sy_auevent = AUE_MPROTECT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 74 = freebsd64_mprotect */
	{ .sy_narg = AS(freebsd64_madvise_args), .sy_call = (sy_call_t *)freebsd64_madvise, .sy_auevent = AUE_MADVISE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 75 = freebsd64_madvise */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 76 = obsolete vhangup */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 77 = obsolete vlimit */
	{ .sy_narg = AS(freebsd64_mincore_args), .sy_call = (sy_call_t *)freebsd64_mincore, .sy_auevent = AUE_MINCORE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 78 = freebsd64_mincore */
	{ .sy_narg = AS(freebsd64_getgroups_args), .sy_call = (sy_call_t *)freebsd64_getgroups, .sy_auevent = AUE_GETGROUPS, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 79 = freebsd64_getgroups */
	{ .sy_narg = AS(freebsd64_setgroups_args), .sy_call = (sy_call_t *)freebsd64_setgroups, .sy_auevent = AUE_SETGROUPS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 80 = freebsd64_setgroups */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_getpgrp, .sy_auevent = AUE_GETPGRP, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 81 = getpgrp */
	{ .sy_narg = AS(setpgid_args), .sy_call = (sy_call_t *)sys_setpgid, .sy_auevent = AUE_SETPGRP, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 82 = setpgid */
	{ .sy_narg = AS(freebsd64_setitimer_args), .sy_call = (sy_call_t *)freebsd64_setitimer, .sy_auevent = AUE_SETITIMER, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 83 = freebsd64_setitimer */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 84 = obsolete owait */
	{ .sy_narg = AS(freebsd64_swapon_args), .sy_call = (sy_call_t *)freebsd64_swapon, .sy_auevent = AUE_SWAPON, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 85 = freebsd64_swapon */
	{ .sy_narg = AS(freebsd64_getitimer_args), .sy_call = (sy_call_t *)freebsd64_getitimer, .sy_auevent = AUE_GETITIMER, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 86 = freebsd64_getitimer */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 87 = obsolete ogethostname */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 88 = obsolete osethostname */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_getdtablesize, .sy_auevent = AUE_GETDTABLESIZE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 89 = getdtablesize */
	{ .sy_narg = AS(dup2_args), .sy_call = (sy_call_t *)sys_dup2, .sy_auevent = AUE_DUP2, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 90 = dup2 */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 91 = reserved for local use */
	{ .sy_narg = AS(freebsd64_fcntl_args), .sy_call = (sy_call_t *)freebsd64_fcntl, .sy_auevent = AUE_FCNTL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 92 = freebsd64_fcntl */
	{ .sy_narg = AS(freebsd64_select_args), .sy_call = (sy_call_t *)freebsd64_select, .sy_auevent = AUE_SELECT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 93 = freebsd64_select */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 94 = reserved for local use */
	{ .sy_narg = AS(fsync_args), .sy_call = (sy_call_t *)sys_fsync, .sy_auevent = AUE_FSYNC, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 95 = fsync */
	{ .sy_narg = AS(setpriority_args), .sy_call = (sy_call_t *)sys_setpriority, .sy_auevent = AUE_SETPRIORITY, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 96 = setpriority */
	{ .sy_narg = AS(socket_args), .sy_call = (sy_call_t *)sys_socket, .sy_auevent = AUE_SOCKET, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 97 = socket */
	{ .sy_narg = AS(freebsd64_connect_args), .sy_call = (sy_call_t *)freebsd64_connect, .sy_auevent = AUE_CONNECT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 98 = freebsd64_connect */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 99 = obsolete oaccept */
	{ .sy_narg = AS(getpriority_args), .sy_call = (sy_call_t *)sys_getpriority, .sy_auevent = AUE_GETPRIORITY, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 100 = getpriority */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 101 = obsolete osend */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 102 = obsolete orecv */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 103 = obsolete osigreturn */
	{ .sy_narg = AS(freebsd64_bind_args), .sy_call = (sy_call_t *)freebsd64_bind, .sy_auevent = AUE_BIND, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 104 = freebsd64_bind */
	{ .sy_narg = AS(freebsd64_setsockopt_args), .sy_call = (sy_call_t *)freebsd64_setsockopt, .sy_auevent = AUE_SETSOCKOPT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 105 = freebsd64_setsockopt */
	{ .sy_narg = AS(listen_args), .sy_call = (sy_call_t *)sys_listen, .sy_auevent = AUE_LISTEN, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 106 = listen */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 107 = obsolete vtimes */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 108 = obsolete osigvec */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 109 = obsolete osigblock */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 110 = obsolete osigsetmask */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 111 = obsolete osigsuspend */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 112 = obsolete osigstack */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 113 = obsolete orecvmsg */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 114 = obsolete osendmsg */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 115 = obsolete vtrace */
	{ .sy_narg = AS(freebsd64_gettimeofday_args), .sy_call = (sy_call_t *)freebsd64_gettimeofday, .sy_auevent = AUE_GETTIMEOFDAY, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 116 = freebsd64_gettimeofday */
	{ .sy_narg = AS(freebsd64_getrusage_args), .sy_call = (sy_call_t *)freebsd64_getrusage, .sy_auevent = AUE_GETRUSAGE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 117 = freebsd64_getrusage */
	{ .sy_narg = AS(freebsd64_getsockopt_args), .sy_call = (sy_call_t *)freebsd64_getsockopt, .sy_auevent = AUE_GETSOCKOPT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 118 = freebsd64_getsockopt */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 119 = reserved for local use */
	{ .sy_narg = AS(freebsd64_readv_args), .sy_call = (sy_call_t *)freebsd64_readv, .sy_auevent = AUE_READV, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 120 = freebsd64_readv */
	{ .sy_narg = AS(freebsd64_writev_args), .sy_call = (sy_call_t *)freebsd64_writev, .sy_auevent = AUE_WRITEV, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 121 = freebsd64_writev */
	{ .sy_narg = AS(freebsd64_settimeofday_args), .sy_call = (sy_call_t *)freebsd64_settimeofday, .sy_auevent = AUE_SETTIMEOFDAY, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 122 = freebsd64_settimeofday */
	{ .sy_narg = AS(fchown_args), .sy_call = (sy_call_t *)sys_fchown, .sy_auevent = AUE_FCHOWN, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 123 = fchown */
	{ .sy_narg = AS(fchmod_args), .sy_call = (sy_call_t *)sys_fchmod, .sy_auevent = AUE_FCHMOD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 124 = fchmod */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 125 = obsolete orecvfrom */
	{ .sy_narg = AS(setreuid_args), .sy_call = (sy_call_t *)sys_setreuid, .sy_auevent = AUE_SETREUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 126 = setreuid */
	{ .sy_narg = AS(setregid_args), .sy_call = (sy_call_t *)sys_setregid, .sy_auevent = AUE_SETREGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 127 = setregid */
	{ .sy_narg = AS(freebsd64_rename_args), .sy_call = (sy_call_t *)freebsd64_rename, .sy_auevent = AUE_RENAME, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 128 = freebsd64_rename */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 129 = obsolete otruncate */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 130 = obsolete oftruncate */
	{ .sy_narg = AS(flock_args), .sy_call = (sy_call_t *)sys_flock, .sy_auevent = AUE_FLOCK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 131 = flock */
	{ .sy_narg = AS(freebsd64_mkfifo_args), .sy_call = (sy_call_t *)freebsd64_mkfifo, .sy_auevent = AUE_MKFIFO, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 132 = freebsd64_mkfifo */
	{ .sy_narg = AS(freebsd64_sendto_args), .sy_call = (sy_call_t *)freebsd64_sendto, .sy_auevent = AUE_SENDTO, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 133 = freebsd64_sendto */
	{ .sy_narg = AS(shutdown_args), .sy_call = (sy_call_t *)sys_shutdown, .sy_auevent = AUE_SHUTDOWN, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 134 = shutdown */
	{ .sy_narg = AS(freebsd64_socketpair_args), .sy_call = (sy_call_t *)freebsd64_socketpair, .sy_auevent = AUE_SOCKETPAIR, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 135 = freebsd64_socketpair */
	{ .sy_narg = AS(freebsd64_mkdir_args), .sy_call = (sy_call_t *)freebsd64_mkdir, .sy_auevent = AUE_MKDIR, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 136 = freebsd64_mkdir */
	{ .sy_narg = AS(freebsd64_rmdir_args), .sy_call = (sy_call_t *)freebsd64_rmdir, .sy_auevent = AUE_RMDIR, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 137 = freebsd64_rmdir */
	{ .sy_narg = AS(freebsd64_utimes_args), .sy_call = (sy_call_t *)freebsd64_utimes, .sy_auevent = AUE_UTIMES, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 138 = freebsd64_utimes */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 139 = obsolete 4.2 sigreturn */
	{ .sy_narg = AS(freebsd64_adjtime_args), .sy_call = (sy_call_t *)freebsd64_adjtime, .sy_auevent = AUE_ADJTIME, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 140 = freebsd64_adjtime */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 141 = obsolete ogetpeername */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 142 = obsolete ogethostid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 143 = obsolete osethostid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 144 = obsolete ogetrlimit */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 145 = obsolete osetrlimit */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 146 = obsolete okillpg */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_setsid, .sy_auevent = AUE_SETSID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 147 = setsid */
	{ .sy_narg = AS(freebsd64_quotactl_args), .sy_call = (sy_call_t *)freebsd64_quotactl, .sy_auevent = AUE_QUOTACTL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 148 = freebsd64_quotactl */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 149 = obsolete oquota */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 150 = obsolete ogetsockname */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 151 = coexecve */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 152 = coexecvec */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 153 = reserved for local use */
	{ .sy_narg = AS(freebsd64_nlm_syscall_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 154 = freebsd64_nlm_syscall */
	{ .sy_narg = AS(freebsd64_nfssvc_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 155 = freebsd64_nfssvc */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 156 = obsolete ogetdirentries */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 157 = obsolete freebsd4_statfs */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 158 = obsolete freebsd4_fstatfs */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 159 = reserved for local use */
	{ .sy_narg = AS(freebsd64_lgetfh_args), .sy_call = (sy_call_t *)freebsd64_lgetfh, .sy_auevent = AUE_LGETFH, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 160 = freebsd64_lgetfh */
	{ .sy_narg = AS(freebsd64_getfh_args), .sy_call = (sy_call_t *)freebsd64_getfh, .sy_auevent = AUE_NFS_GETFH, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 161 = freebsd64_getfh */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 162 = obsolete freebsd4_getdomainname */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 163 = obsolete freebsd4_setdomainname */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 164 = obsolete freebsd4_uname */
	{ .sy_narg = AS(freebsd64_sysarch_args), .sy_call = (sy_call_t *)freebsd64_sysarch, .sy_auevent = AUE_SYSARCH, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 165 = freebsd64_sysarch */
	{ .sy_narg = AS(freebsd64_rtprio_args), .sy_call = (sy_call_t *)freebsd64_rtprio, .sy_auevent = AUE_RTPRIO, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 166 = freebsd64_rtprio */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 167 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 168 = reserved for local use */
	{ .sy_narg = AS(freebsd64_semsys_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 169 = freebsd64_semsys */
	{ .sy_narg = AS(freebsd64_msgsys_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 170 = freebsd64_msgsys */
	{ .sy_narg = AS(freebsd64_shmsys_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 171 = freebsd64_shmsys */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 172 = reserved for local use */
	{ compat6(AS(freebsd6_freebsd64_pread_args),freebsd64_pread), .sy_auevent = AUE_PREAD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 173 = freebsd6 freebsd64_pread */
	{ compat6(AS(freebsd6_freebsd64_pwrite_args),freebsd64_pwrite), .sy_auevent = AUE_PWRITE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 174 = freebsd6 freebsd64_pwrite */
	{ .sy_narg = AS(setfib_args), .sy_call = (sy_call_t *)sys_setfib, .sy_auevent = AUE_SETFIB, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 175 = setfib */
	{ .sy_narg = AS(freebsd64_ntp_adjtime_args), .sy_call = (sy_call_t *)freebsd64_ntp_adjtime, .sy_auevent = AUE_NTP_ADJTIME, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 176 = freebsd64_ntp_adjtime */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 177 = _cosetup */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 178 = coregister */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 179 = colookup */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 180 = copark */
	{ .sy_narg = AS(setgid_args), .sy_call = (sy_call_t *)sys_setgid, .sy_auevent = AUE_SETGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 181 = setgid */
	{ .sy_narg = AS(setegid_args), .sy_call = (sy_call_t *)sys_setegid, .sy_auevent = AUE_SETEGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 182 = setegid */
	{ .sy_narg = AS(seteuid_args), .sy_call = (sy_call_t *)sys_seteuid, .sy_auevent = AUE_SETEUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 183 = seteuid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 184 = obsolete lfs_bmapv */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 185 = obsolete lfs_markv */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 186 = obsolete lfs_segclean */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 187 = obsolete lfs_segwait */
	{ compat11(AS(freebsd11_freebsd64_stat_args),freebsd64_stat), .sy_auevent = AUE_STAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 188 = freebsd11 freebsd64_stat */
	{ compat11(AS(freebsd11_freebsd64_fstat_args),freebsd64_fstat), .sy_auevent = AUE_FSTAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 189 = freebsd11 freebsd64_fstat */
	{ compat11(AS(freebsd11_freebsd64_lstat_args),freebsd64_lstat), .sy_auevent = AUE_LSTAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 190 = freebsd11 freebsd64_lstat */
	{ .sy_narg = AS(freebsd64_pathconf_args), .sy_call = (sy_call_t *)freebsd64_pathconf, .sy_auevent = AUE_PATHCONF, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 191 = freebsd64_pathconf */
	{ .sy_narg = AS(fpathconf_args), .sy_call = (sy_call_t *)sys_fpathconf, .sy_auevent = AUE_FPATHCONF, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 192 = fpathconf */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 193 = cogetpid */
	{ .sy_narg = AS(freebsd64_getrlimit_args), .sy_call = (sy_call_t *)freebsd64_getrlimit, .sy_auevent = AUE_GETRLIMIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 194 = freebsd64_getrlimit */
	{ .sy_narg = AS(freebsd64_setrlimit_args), .sy_call = (sy_call_t *)freebsd64_setrlimit, .sy_auevent = AUE_SETRLIMIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 195 = freebsd64_setrlimit */
	{ compat11(AS(freebsd11_freebsd64_getdirentries_args),freebsd64_getdirentries), .sy_auevent = AUE_GETDIRENTRIES, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 196 = freebsd11 freebsd64_getdirentries */
	{ compat6(AS(freebsd6_freebsd64_mmap_args),freebsd64_mmap), .sy_auevent = AUE_MMAP, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 197 = freebsd6 freebsd64_mmap */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },		/* 198 = __syscall */
	{ compat6(AS(freebsd6_lseek_args),lseek), .sy_auevent = AUE_LSEEK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 199 = freebsd6 lseek */
	{ compat6(AS(freebsd6_freebsd64_truncate_args),freebsd64_truncate), .sy_auevent = AUE_TRUNCATE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 200 = freebsd6 freebsd64_truncate */
	{ compat6(AS(freebsd6_ftruncate_args),ftruncate), .sy_auevent = AUE_FTRUNCATE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 201 = freebsd6 ftruncate */
	{ .sy_narg = AS(freebsd64___sysctl_args), .sy_call = (sy_call_t *)freebsd64___sysctl, .sy_auevent = AUE_SYSCTL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 202 = freebsd64___sysctl */
	{ .sy_narg = AS(freebsd64_mlock_args), .sy_call = (sy_call_t *)freebsd64_mlock, .sy_auevent = AUE_MLOCK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 203 = freebsd64_mlock */
	{ .sy_narg = AS(freebsd64_munlock_args), .sy_call = (sy_call_t *)freebsd64_munlock, .sy_auevent = AUE_MUNLOCK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 204 = freebsd64_munlock */
	{ .sy_narg = AS(freebsd64_undelete_args), .sy_call = (sy_call_t *)freebsd64_undelete, .sy_auevent = AUE_UNDELETE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 205 = freebsd64_undelete */
	{ .sy_narg = AS(freebsd64_futimes_args), .sy_call = (sy_call_t *)freebsd64_futimes, .sy_auevent = AUE_FUTIMES, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 206 = freebsd64_futimes */
	{ .sy_narg = AS(getpgid_args), .sy_call = (sy_call_t *)sys_getpgid, .sy_auevent = AUE_GETPGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 207 = getpgid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 208 = reserved for local use */
	{ .sy_narg = AS(freebsd64_poll_args), .sy_call = (sy_call_t *)freebsd64_poll, .sy_auevent = AUE_POLL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 209 = freebsd64_poll */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 210 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 211 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 212 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 213 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 214 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 215 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 216 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 217 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 218 = lkmnosys */
	{ .sy_narg = AS(nosys_args), .sy_call = (sy_call_t *)lkmnosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 219 = lkmnosys */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },		/* 220 = freebsd7 freebsd64___semctl */
	{ .sy_narg = AS(semget_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 221 = semget */
	{ .sy_narg = AS(freebsd64_semop_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 222 = freebsd64_semop */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 223 = obsolete semconfig */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },		/* 224 = freebsd7 freebsd64_msgctl */
	{ .sy_narg = AS(msgget_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 225 = msgget */
	{ .sy_narg = AS(freebsd64_msgsnd_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 226 = freebsd64_msgsnd */
	{ .sy_narg = AS(freebsd64_msgrcv_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 227 = freebsd64_msgrcv */
	{ .sy_narg = AS(freebsd64_shmat_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 228 = freebsd64_shmat */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },		/* 229 = freebsd7 freebsd64_shmctl */
	{ .sy_narg = AS(freebsd64_shmdt_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 230 = freebsd64_shmdt */
	{ .sy_narg = AS(shmget_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 231 = shmget */
	{ .sy_narg = AS(freebsd64_clock_gettime_args), .sy_call = (sy_call_t *)freebsd64_clock_gettime, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 232 = freebsd64_clock_gettime */
	{ .sy_narg = AS(freebsd64_clock_settime_args), .sy_call = (sy_call_t *)freebsd64_clock_settime, .sy_auevent = AUE_CLOCK_SETTIME, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 233 = freebsd64_clock_settime */
	{ .sy_narg = AS(freebsd64_clock_getres_args), .sy_call = (sy_call_t *)freebsd64_clock_getres, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 234 = freebsd64_clock_getres */
	{ .sy_narg = AS(freebsd64_ktimer_create_args), .sy_call = (sy_call_t *)freebsd64_ktimer_create, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 235 = freebsd64_ktimer_create */
	{ .sy_narg = AS(ktimer_delete_args), .sy_call = (sy_call_t *)sys_ktimer_delete, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 236 = ktimer_delete */
	{ .sy_narg = AS(freebsd64_ktimer_settime_args), .sy_call = (sy_call_t *)freebsd64_ktimer_settime, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 237 = freebsd64_ktimer_settime */
	{ .sy_narg = AS(freebsd64_ktimer_gettime_args), .sy_call = (sy_call_t *)freebsd64_ktimer_gettime, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 238 = freebsd64_ktimer_gettime */
	{ .sy_narg = AS(ktimer_getoverrun_args), .sy_call = (sy_call_t *)sys_ktimer_getoverrun, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 239 = ktimer_getoverrun */
	{ .sy_narg = AS(freebsd64_nanosleep_args), .sy_call = (sy_call_t *)freebsd64_nanosleep, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 240 = freebsd64_nanosleep */
	{ .sy_narg = AS(freebsd64_ffclock_getcounter_args), .sy_call = (sy_call_t *)freebsd64_ffclock_getcounter, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 241 = freebsd64_ffclock_getcounter */
	{ .sy_narg = AS(freebsd64_ffclock_setestimate_args), .sy_call = (sy_call_t *)freebsd64_ffclock_setestimate, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 242 = freebsd64_ffclock_setestimate */
	{ .sy_narg = AS(freebsd64_ffclock_getestimate_args), .sy_call = (sy_call_t *)freebsd64_ffclock_getestimate, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 243 = freebsd64_ffclock_getestimate */
	{ .sy_narg = AS(freebsd64_clock_nanosleep_args), .sy_call = (sy_call_t *)freebsd64_clock_nanosleep, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 244 = freebsd64_clock_nanosleep */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 245 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 246 = reserved for local use */
	{ .sy_narg = AS(freebsd64_clock_getcpuclockid2_args), .sy_call = (sy_call_t *)freebsd64_clock_getcpuclockid2, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 247 = freebsd64_clock_getcpuclockid2 */
	{ .sy_narg = AS(freebsd64_ntp_gettime_args), .sy_call = (sy_call_t *)freebsd64_ntp_gettime, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 248 = freebsd64_ntp_gettime */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 249 = reserved for local use */
	{ .sy_narg = AS(freebsd64_minherit_args), .sy_call = (sy_call_t *)freebsd64_minherit, .sy_auevent = AUE_MINHERIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 250 = freebsd64_minherit */
	{ .sy_narg = AS(rfork_args), .sy_call = (sy_call_t *)sys_rfork, .sy_auevent = AUE_RFORK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 251 = rfork */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 252 = obsolete openbsd_poll */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_issetugid, .sy_auevent = AUE_ISSETUGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 253 = issetugid */
	{ .sy_narg = AS(freebsd64_lchown_args), .sy_call = (sy_call_t *)freebsd64_lchown, .sy_auevent = AUE_LCHOWN, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 254 = freebsd64_lchown */
	{ .sy_narg = AS(freebsd64_aio_read_args), .sy_call = (sy_call_t *)freebsd64_aio_read, .sy_auevent = AUE_AIO_READ, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 255 = freebsd64_aio_read */
	{ .sy_narg = AS(freebsd64_aio_write_args), .sy_call = (sy_call_t *)freebsd64_aio_write, .sy_auevent = AUE_AIO_WRITE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 256 = freebsd64_aio_write */
	{ .sy_narg = AS(freebsd64_lio_listio_args), .sy_call = (sy_call_t *)freebsd64_lio_listio, .sy_auevent = AUE_LIO_LISTIO, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 257 = freebsd64_lio_listio */
	{ .sy_narg = AS(freebsd64_kbounce_args), .sy_call = (sy_call_t *)freebsd64_kbounce, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 258 = freebsd64_kbounce */
	{ .sy_narg = AS(freebsd64_flag_captured_args), .sy_call = (sy_call_t *)freebsd64_flag_captured, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 259 = freebsd64_flag_captured */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 260 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 261 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 262 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 263 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 264 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 265 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 266 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 267 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 268 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 269 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 270 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 271 = reserved for local use */
	{ compat11(AS(freebsd11_freebsd64_getdents_args),freebsd64_getdents), .sy_auevent = AUE_O_GETDENTS, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 272 = freebsd11 freebsd64_getdents */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 273 = reserved for local use */
	{ .sy_narg = AS(freebsd64_lchmod_args), .sy_call = (sy_call_t *)freebsd64_lchmod, .sy_auevent = AUE_LCHMOD, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 274 = freebsd64_lchmod */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 275 = obsolete netbsd_lchown */
	{ .sy_narg = AS(freebsd64_lutimes_args), .sy_call = (sy_call_t *)freebsd64_lutimes, .sy_auevent = AUE_LUTIMES, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 276 = freebsd64_lutimes */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 277 = obsolete netbsd_msync */
	{ compat11(AS(freebsd11_freebsd64_nstat_args),freebsd64_nstat), .sy_auevent = AUE_STAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 278 = freebsd11 freebsd64_nstat */
	{ compat11(AS(freebsd11_freebsd64_nfstat_args),freebsd64_nfstat), .sy_auevent = AUE_FSTAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 279 = freebsd11 freebsd64_nfstat */
	{ compat11(AS(freebsd11_freebsd64_nlstat_args),freebsd64_nlstat), .sy_auevent = AUE_LSTAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 280 = freebsd11 freebsd64_nlstat */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 281 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 282 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 283 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 284 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 285 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 286 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 287 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 288 = reserved for local use */
	{ .sy_narg = AS(freebsd64_preadv_args), .sy_call = (sy_call_t *)freebsd64_preadv, .sy_auevent = AUE_PREADV, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 289 = freebsd64_preadv */
	{ .sy_narg = AS(freebsd64_pwritev_args), .sy_call = (sy_call_t *)freebsd64_pwritev, .sy_auevent = AUE_PWRITEV, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 290 = freebsd64_pwritev */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 291 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 292 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 293 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 294 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 295 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 296 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 297 = obsolete freebsd4_fhstatfs */
	{ .sy_narg = AS(freebsd64_fhopen_args), .sy_call = (sy_call_t *)freebsd64_fhopen, .sy_auevent = AUE_FHOPEN, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 298 = freebsd64_fhopen */
	{ compat11(AS(freebsd11_freebsd64_fhstat_args),freebsd64_fhstat), .sy_auevent = AUE_FHSTAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 299 = freebsd11 freebsd64_fhstat */
	{ .sy_narg = AS(modnext_args), .sy_call = (sy_call_t *)sys_modnext, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 300 = modnext */
	{ .sy_narg = AS(freebsd64_modstat_args), .sy_call = (sy_call_t *)freebsd64_modstat, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 301 = freebsd64_modstat */
	{ .sy_narg = AS(modfnext_args), .sy_call = (sy_call_t *)sys_modfnext, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 302 = modfnext */
	{ .sy_narg = AS(freebsd64_modfind_args), .sy_call = (sy_call_t *)freebsd64_modfind, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 303 = freebsd64_modfind */
	{ .sy_narg = AS(freebsd64_kldload_args), .sy_call = (sy_call_t *)freebsd64_kldload, .sy_auevent = AUE_MODLOAD, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 304 = freebsd64_kldload */
	{ .sy_narg = AS(kldunload_args), .sy_call = (sy_call_t *)sys_kldunload, .sy_auevent = AUE_MODUNLOAD, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 305 = kldunload */
	{ .sy_narg = AS(freebsd64_kldfind_args), .sy_call = (sy_call_t *)freebsd64_kldfind, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 306 = freebsd64_kldfind */
	{ .sy_narg = AS(kldnext_args), .sy_call = (sy_call_t *)sys_kldnext, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 307 = kldnext */
	{ .sy_narg = AS(freebsd64_kldstat_args), .sy_call = (sy_call_t *)freebsd64_kldstat, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 308 = freebsd64_kldstat */
	{ .sy_narg = AS(kldfirstmod_args), .sy_call = (sy_call_t *)sys_kldfirstmod, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 309 = kldfirstmod */
	{ .sy_narg = AS(getsid_args), .sy_call = (sy_call_t *)sys_getsid, .sy_auevent = AUE_GETSID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 310 = getsid */
	{ .sy_narg = AS(setresuid_args), .sy_call = (sy_call_t *)sys_setresuid, .sy_auevent = AUE_SETRESUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 311 = setresuid */
	{ .sy_narg = AS(setresgid_args), .sy_call = (sy_call_t *)sys_setresgid, .sy_auevent = AUE_SETRESGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 312 = setresgid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 313 = obsolete signanosleep */
	{ .sy_narg = AS(freebsd64_aio_return_args), .sy_call = (sy_call_t *)freebsd64_aio_return, .sy_auevent = AUE_AIO_RETURN, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 314 = freebsd64_aio_return */
	{ .sy_narg = AS(freebsd64_aio_suspend_args), .sy_call = (sy_call_t *)freebsd64_aio_suspend, .sy_auevent = AUE_AIO_SUSPEND, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 315 = freebsd64_aio_suspend */
	{ .sy_narg = AS(freebsd64_aio_cancel_args), .sy_call = (sy_call_t *)freebsd64_aio_cancel, .sy_auevent = AUE_AIO_CANCEL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 316 = freebsd64_aio_cancel */
	{ .sy_narg = AS(freebsd64_aio_error_args), .sy_call = (sy_call_t *)freebsd64_aio_error, .sy_auevent = AUE_AIO_ERROR, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 317 = freebsd64_aio_error */
	{ compat6(AS(freebsd6_freebsd64_aio_read_args),freebsd64_aio_read), .sy_auevent = AUE_AIO_READ, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 318 = freebsd6 freebsd64_aio_read */
	{ compat6(AS(freebsd6_freebsd64_aio_write_args),freebsd64_aio_write), .sy_auevent = AUE_AIO_WRITE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 319 = freebsd6 freebsd64_aio_write */
	{ compat6(AS(freebsd6_freebsd64_lio_listio_args),freebsd64_lio_listio), .sy_auevent = AUE_LIO_LISTIO, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 320 = freebsd6 freebsd64_lio_listio */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_yield, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 321 = yield */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 322 = obsolete thr_sleep */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 323 = obsolete thr_wakeup */
	{ .sy_narg = AS(mlockall_args), .sy_call = (sy_call_t *)sys_mlockall, .sy_auevent = AUE_MLOCKALL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 324 = mlockall */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_munlockall, .sy_auevent = AUE_MUNLOCKALL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 325 = munlockall */
	{ .sy_narg = AS(freebsd64___getcwd_args), .sy_call = (sy_call_t *)freebsd64___getcwd, .sy_auevent = AUE_GETCWD, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 326 = freebsd64___getcwd */
	{ .sy_narg = AS(freebsd64_sched_setparam_args), .sy_call = (sy_call_t *)freebsd64_sched_setparam, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 327 = freebsd64_sched_setparam */
	{ .sy_narg = AS(freebsd64_sched_getparam_args), .sy_call = (sy_call_t *)freebsd64_sched_getparam, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 328 = freebsd64_sched_getparam */
	{ .sy_narg = AS(freebsd64_sched_setscheduler_args), .sy_call = (sy_call_t *)freebsd64_sched_setscheduler, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 329 = freebsd64_sched_setscheduler */
	{ .sy_narg = AS(sched_getscheduler_args), .sy_call = (sy_call_t *)sys_sched_getscheduler, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 330 = sched_getscheduler */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_sched_yield, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 331 = sched_yield */
	{ .sy_narg = AS(sched_get_priority_max_args), .sy_call = (sy_call_t *)sys_sched_get_priority_max, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 332 = sched_get_priority_max */
	{ .sy_narg = AS(sched_get_priority_min_args), .sy_call = (sy_call_t *)sys_sched_get_priority_min, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 333 = sched_get_priority_min */
	{ .sy_narg = AS(freebsd64_sched_rr_get_interval_args), .sy_call = (sy_call_t *)freebsd64_sched_rr_get_interval, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 334 = freebsd64_sched_rr_get_interval */
	{ .sy_narg = AS(freebsd64_utrace_args), .sy_call = (sy_call_t *)freebsd64_utrace, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 335 = freebsd64_utrace */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 336 = obsolete freebsd4_sendfile */
	{ .sy_narg = AS(freebsd64_kldsym_args), .sy_call = (sy_call_t *)freebsd64_kldsym, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 337 = freebsd64_kldsym */
	{ .sy_narg = AS(freebsd64_jail_args), .sy_call = (sy_call_t *)freebsd64_jail, .sy_auevent = AUE_JAIL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 338 = freebsd64_jail */
	{ .sy_narg = AS(freebsd64_nnpfs_syscall_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 339 = freebsd64_nnpfs_syscall */
	{ .sy_narg = AS(freebsd64_sigprocmask_args), .sy_call = (sy_call_t *)freebsd64_sigprocmask, .sy_auevent = AUE_SIGPROCMASK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 340 = freebsd64_sigprocmask */
	{ .sy_narg = AS(freebsd64_sigsuspend_args), .sy_call = (sy_call_t *)freebsd64_sigsuspend, .sy_auevent = AUE_SIGSUSPEND, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 341 = freebsd64_sigsuspend */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 342 = obsolete freebsd4_sigaction */
	{ .sy_narg = AS(freebsd64_sigpending_args), .sy_call = (sy_call_t *)freebsd64_sigpending, .sy_auevent = AUE_SIGPENDING, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 343 = freebsd64_sigpending */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 344 = obsolete freebsd4_sigreturn */
	{ .sy_narg = AS(freebsd64_sigtimedwait_args), .sy_call = (sy_call_t *)freebsd64_sigtimedwait, .sy_auevent = AUE_SIGWAIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 345 = freebsd64_sigtimedwait */
	{ .sy_narg = AS(freebsd64_sigwaitinfo_args), .sy_call = (sy_call_t *)freebsd64_sigwaitinfo, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 346 = freebsd64_sigwaitinfo */
	{ .sy_narg = AS(freebsd64___acl_get_file_args), .sy_call = (sy_call_t *)freebsd64___acl_get_file, .sy_auevent = AUE_ACL_GET_FILE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 347 = freebsd64___acl_get_file */
	{ .sy_narg = AS(freebsd64___acl_set_file_args), .sy_call = (sy_call_t *)freebsd64___acl_set_file, .sy_auevent = AUE_ACL_SET_FILE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 348 = freebsd64___acl_set_file */
	{ .sy_narg = AS(freebsd64___acl_get_fd_args), .sy_call = (sy_call_t *)freebsd64___acl_get_fd, .sy_auevent = AUE_ACL_GET_FD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 349 = freebsd64___acl_get_fd */
	{ .sy_narg = AS(freebsd64___acl_set_fd_args), .sy_call = (sy_call_t *)freebsd64___acl_set_fd, .sy_auevent = AUE_ACL_SET_FD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 350 = freebsd64___acl_set_fd */
	{ .sy_narg = AS(freebsd64___acl_delete_file_args), .sy_call = (sy_call_t *)freebsd64___acl_delete_file, .sy_auevent = AUE_ACL_DELETE_FILE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 351 = freebsd64___acl_delete_file */
	{ .sy_narg = AS(__acl_delete_fd_args), .sy_call = (sy_call_t *)sys___acl_delete_fd, .sy_auevent = AUE_ACL_DELETE_FD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 352 = __acl_delete_fd */
	{ .sy_narg = AS(freebsd64___acl_aclcheck_file_args), .sy_call = (sy_call_t *)freebsd64___acl_aclcheck_file, .sy_auevent = AUE_ACL_CHECK_FILE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 353 = freebsd64___acl_aclcheck_file */
	{ .sy_narg = AS(freebsd64___acl_aclcheck_fd_args), .sy_call = (sy_call_t *)freebsd64___acl_aclcheck_fd, .sy_auevent = AUE_ACL_CHECK_FD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 354 = freebsd64___acl_aclcheck_fd */
	{ .sy_narg = AS(freebsd64_extattrctl_args), .sy_call = (sy_call_t *)freebsd64_extattrctl, .sy_auevent = AUE_EXTATTRCTL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 355 = freebsd64_extattrctl */
	{ .sy_narg = AS(freebsd64_extattr_set_file_args), .sy_call = (sy_call_t *)freebsd64_extattr_set_file, .sy_auevent = AUE_EXTATTR_SET_FILE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 356 = freebsd64_extattr_set_file */
	{ .sy_narg = AS(freebsd64_extattr_get_file_args), .sy_call = (sy_call_t *)freebsd64_extattr_get_file, .sy_auevent = AUE_EXTATTR_GET_FILE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 357 = freebsd64_extattr_get_file */
	{ .sy_narg = AS(freebsd64_extattr_delete_file_args), .sy_call = (sy_call_t *)freebsd64_extattr_delete_file, .sy_auevent = AUE_EXTATTR_DELETE_FILE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 358 = freebsd64_extattr_delete_file */
	{ .sy_narg = AS(freebsd64_aio_waitcomplete_args), .sy_call = (sy_call_t *)freebsd64_aio_waitcomplete, .sy_auevent = AUE_AIO_WAITCOMPLETE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 359 = freebsd64_aio_waitcomplete */
	{ .sy_narg = AS(freebsd64_getresuid_args), .sy_call = (sy_call_t *)freebsd64_getresuid, .sy_auevent = AUE_GETRESUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 360 = freebsd64_getresuid */
	{ .sy_narg = AS(freebsd64_getresgid_args), .sy_call = (sy_call_t *)freebsd64_getresgid, .sy_auevent = AUE_GETRESGID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 361 = freebsd64_getresgid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_kqueue, .sy_auevent = AUE_KQUEUE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 362 = kqueue */
	{ compat11(AS(freebsd11_freebsd64_kevent_args),freebsd64_kevent), .sy_auevent = AUE_KEVENT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 363 = freebsd11 freebsd64_kevent */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 364 = obsolete __cap_get_proc */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 365 = obsolete __cap_set_proc */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 366 = obsolete __cap_get_fd */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 367 = obsolete __cap_get_file */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 368 = obsolete __cap_set_fd */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 369 = obsolete __cap_set_file */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 370 = reserved for local use */
	{ .sy_narg = AS(freebsd64_extattr_set_fd_args), .sy_call = (sy_call_t *)freebsd64_extattr_set_fd, .sy_auevent = AUE_EXTATTR_SET_FD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 371 = freebsd64_extattr_set_fd */
	{ .sy_narg = AS(freebsd64_extattr_get_fd_args), .sy_call = (sy_call_t *)freebsd64_extattr_get_fd, .sy_auevent = AUE_EXTATTR_GET_FD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 372 = freebsd64_extattr_get_fd */
	{ .sy_narg = AS(freebsd64_extattr_delete_fd_args), .sy_call = (sy_call_t *)freebsd64_extattr_delete_fd, .sy_auevent = AUE_EXTATTR_DELETE_FD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 373 = freebsd64_extattr_delete_fd */
	{ .sy_narg = AS(__setugid_args), .sy_call = (sy_call_t *)sys___setugid, .sy_auevent = AUE_SETUGID, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 374 = __setugid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 375 = obsolete nfsclnt */
	{ .sy_narg = AS(freebsd64_eaccess_args), .sy_call = (sy_call_t *)freebsd64_eaccess, .sy_auevent = AUE_EACCESS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 376 = freebsd64_eaccess */
	{ .sy_narg = AS(afs3_syscall_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 377 = afs3_syscall */
	{ .sy_narg = AS(freebsd64_nmount_args), .sy_call = (sy_call_t *)freebsd64_nmount, .sy_auevent = AUE_NMOUNT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 378 = freebsd64_nmount */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 379 = obsolete kse_exit */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 380 = obsolete kse_wakeup */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 381 = obsolete kse_create */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 382 = obsolete kse_thr_interrupt */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 383 = obsolete kse_release */
	{ .sy_narg = AS(freebsd64___mac_get_proc_args), .sy_call = (sy_call_t *)freebsd64___mac_get_proc, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 384 = freebsd64___mac_get_proc */
	{ .sy_narg = AS(freebsd64___mac_set_proc_args), .sy_call = (sy_call_t *)freebsd64___mac_set_proc, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 385 = freebsd64___mac_set_proc */
	{ .sy_narg = AS(freebsd64___mac_get_fd_args), .sy_call = (sy_call_t *)freebsd64___mac_get_fd, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 386 = freebsd64___mac_get_fd */
	{ .sy_narg = AS(freebsd64___mac_get_file_args), .sy_call = (sy_call_t *)freebsd64___mac_get_file, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 387 = freebsd64___mac_get_file */
	{ .sy_narg = AS(freebsd64___mac_set_fd_args), .sy_call = (sy_call_t *)freebsd64___mac_set_fd, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 388 = freebsd64___mac_set_fd */
	{ .sy_narg = AS(freebsd64___mac_set_file_args), .sy_call = (sy_call_t *)freebsd64___mac_set_file, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 389 = freebsd64___mac_set_file */
	{ .sy_narg = AS(freebsd64_kenv_args), .sy_call = (sy_call_t *)freebsd64_kenv, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 390 = freebsd64_kenv */
	{ .sy_narg = AS(freebsd64_lchflags_args), .sy_call = (sy_call_t *)freebsd64_lchflags, .sy_auevent = AUE_LCHFLAGS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 391 = freebsd64_lchflags */
	{ .sy_narg = AS(freebsd64_uuidgen_args), .sy_call = (sy_call_t *)freebsd64_uuidgen, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 392 = freebsd64_uuidgen */
	{ .sy_narg = AS(freebsd64_sendfile_args), .sy_call = (sy_call_t *)freebsd64_sendfile, .sy_auevent = AUE_SENDFILE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 393 = freebsd64_sendfile */
	{ .sy_narg = AS(freebsd64_mac_syscall_args), .sy_call = (sy_call_t *)freebsd64_mac_syscall, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 394 = freebsd64_mac_syscall */
	{ compat11(AS(freebsd11_freebsd64_getfsstat_args),freebsd64_getfsstat), .sy_auevent = AUE_GETFSSTAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 395 = freebsd11 freebsd64_getfsstat */
	{ compat11(AS(freebsd11_freebsd64_statfs_args),freebsd64_statfs), .sy_auevent = AUE_STATFS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 396 = freebsd11 freebsd64_statfs */
	{ compat11(AS(freebsd11_freebsd64_fstatfs_args),freebsd64_fstatfs), .sy_auevent = AUE_FSTATFS, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 397 = freebsd11 freebsd64_fstatfs */
	{ compat11(AS(freebsd11_freebsd64_fhstatfs_args),freebsd64_fhstatfs), .sy_auevent = AUE_FHSTATFS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 398 = freebsd11 freebsd64_fhstatfs */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 399 = reserved for local use */
	{ .sy_narg = AS(ksem_close_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 400 = ksem_close */
	{ .sy_narg = AS(ksem_post_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 401 = ksem_post */
	{ .sy_narg = AS(ksem_wait_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 402 = ksem_wait */
	{ .sy_narg = AS(ksem_trywait_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 403 = ksem_trywait */
	{ .sy_narg = AS(freebsd64_ksem_init_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 404 = freebsd64_ksem_init */
	{ .sy_narg = AS(freebsd64_ksem_open_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 405 = freebsd64_ksem_open */
	{ .sy_narg = AS(freebsd64_ksem_unlink_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 406 = freebsd64_ksem_unlink */
	{ .sy_narg = AS(freebsd64_ksem_getvalue_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 407 = freebsd64_ksem_getvalue */
	{ .sy_narg = AS(ksem_destroy_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 408 = ksem_destroy */
	{ .sy_narg = AS(freebsd64___mac_get_pid_args), .sy_call = (sy_call_t *)freebsd64___mac_get_pid, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 409 = freebsd64___mac_get_pid */
	{ .sy_narg = AS(freebsd64___mac_get_link_args), .sy_call = (sy_call_t *)freebsd64___mac_get_link, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 410 = freebsd64___mac_get_link */
	{ .sy_narg = AS(freebsd64___mac_set_link_args), .sy_call = (sy_call_t *)freebsd64___mac_set_link, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 411 = freebsd64___mac_set_link */
	{ .sy_narg = AS(freebsd64_extattr_set_link_args), .sy_call = (sy_call_t *)freebsd64_extattr_set_link, .sy_auevent = AUE_EXTATTR_SET_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 412 = freebsd64_extattr_set_link */
	{ .sy_narg = AS(freebsd64_extattr_get_link_args), .sy_call = (sy_call_t *)freebsd64_extattr_get_link, .sy_auevent = AUE_EXTATTR_GET_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 413 = freebsd64_extattr_get_link */
	{ .sy_narg = AS(freebsd64_extattr_delete_link_args), .sy_call = (sy_call_t *)freebsd64_extattr_delete_link, .sy_auevent = AUE_EXTATTR_DELETE_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 414 = freebsd64_extattr_delete_link */
	{ .sy_narg = AS(freebsd64___mac_execve_args), .sy_call = (sy_call_t *)freebsd64___mac_execve, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 415 = freebsd64___mac_execve */
	{ .sy_narg = AS(freebsd64_sigaction_args), .sy_call = (sy_call_t *)freebsd64_sigaction, .sy_auevent = AUE_SIGACTION, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 416 = freebsd64_sigaction */
	{ .sy_narg = AS(freebsd64_sigreturn_args), .sy_call = (sy_call_t *)freebsd64_sigreturn, .sy_auevent = AUE_SIGRETURN, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 417 = freebsd64_sigreturn */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 418 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 419 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 420 = reserved for local use */
	{ .sy_narg = AS(freebsd64_getcontext_args), .sy_call = (sy_call_t *)freebsd64_getcontext, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 421 = freebsd64_getcontext */
	{ .sy_narg = AS(freebsd64_setcontext_args), .sy_call = (sy_call_t *)freebsd64_setcontext, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 422 = freebsd64_setcontext */
	{ .sy_narg = AS(freebsd64_swapcontext_args), .sy_call = (sy_call_t *)freebsd64_swapcontext, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 423 = freebsd64_swapcontext */
	{ compat13(AS(freebsd13_freebsd64_swapoff_args),freebsd64_swapoff), .sy_auevent = AUE_SWAPOFF, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 424 = freebsd13 freebsd64_swapoff */
	{ .sy_narg = AS(freebsd64___acl_get_link_args), .sy_call = (sy_call_t *)freebsd64___acl_get_link, .sy_auevent = AUE_ACL_GET_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 425 = freebsd64___acl_get_link */
	{ .sy_narg = AS(freebsd64___acl_set_link_args), .sy_call = (sy_call_t *)freebsd64___acl_set_link, .sy_auevent = AUE_ACL_SET_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 426 = freebsd64___acl_set_link */
	{ .sy_narg = AS(freebsd64___acl_delete_link_args), .sy_call = (sy_call_t *)freebsd64___acl_delete_link, .sy_auevent = AUE_ACL_DELETE_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 427 = freebsd64___acl_delete_link */
	{ .sy_narg = AS(freebsd64___acl_aclcheck_link_args), .sy_call = (sy_call_t *)freebsd64___acl_aclcheck_link, .sy_auevent = AUE_ACL_CHECK_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 428 = freebsd64___acl_aclcheck_link */
	{ .sy_narg = AS(freebsd64_sigwait_args), .sy_call = (sy_call_t *)freebsd64_sigwait, .sy_auevent = AUE_SIGWAIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 429 = freebsd64_sigwait */
	{ .sy_narg = AS(freebsd64_thr_create_args), .sy_call = (sy_call_t *)freebsd64_thr_create, .sy_auevent = AUE_THR_CREATE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 430 = freebsd64_thr_create */
	{ .sy_narg = AS(freebsd64_thr_exit_args), .sy_call = (sy_call_t *)freebsd64_thr_exit, .sy_auevent = AUE_THR_EXIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 431 = freebsd64_thr_exit */
	{ .sy_narg = AS(freebsd64_thr_self_args), .sy_call = (sy_call_t *)freebsd64_thr_self, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 432 = freebsd64_thr_self */
	{ .sy_narg = AS(thr_kill_args), .sy_call = (sy_call_t *)sys_thr_kill, .sy_auevent = AUE_THR_KILL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 433 = thr_kill */
	{ compat10(AS(freebsd10_freebsd64__umtx_lock_args),freebsd64__umtx_lock), .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 434 = freebsd10 freebsd64__umtx_lock */
	{ compat10(AS(freebsd10_freebsd64__umtx_unlock_args),freebsd64__umtx_unlock), .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 435 = freebsd10 freebsd64__umtx_unlock */
	{ .sy_narg = AS(jail_attach_args), .sy_call = (sy_call_t *)sys_jail_attach, .sy_auevent = AUE_JAIL_ATTACH, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 436 = jail_attach */
	{ .sy_narg = AS(freebsd64_extattr_list_fd_args), .sy_call = (sy_call_t *)freebsd64_extattr_list_fd, .sy_auevent = AUE_EXTATTR_LIST_FD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 437 = freebsd64_extattr_list_fd */
	{ .sy_narg = AS(freebsd64_extattr_list_file_args), .sy_call = (sy_call_t *)freebsd64_extattr_list_file, .sy_auevent = AUE_EXTATTR_LIST_FILE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 438 = freebsd64_extattr_list_file */
	{ .sy_narg = AS(freebsd64_extattr_list_link_args), .sy_call = (sy_call_t *)freebsd64_extattr_list_link, .sy_auevent = AUE_EXTATTR_LIST_LINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 439 = freebsd64_extattr_list_link */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 440 = obsolete kse_switchin */
	{ .sy_narg = AS(freebsd64_ksem_timedwait_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 441 = freebsd64_ksem_timedwait */
	{ .sy_narg = AS(freebsd64_thr_suspend_args), .sy_call = (sy_call_t *)freebsd64_thr_suspend, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 442 = freebsd64_thr_suspend */
	{ .sy_narg = AS(thr_wake_args), .sy_call = (sy_call_t *)sys_thr_wake, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 443 = thr_wake */
	{ .sy_narg = AS(kldunloadf_args), .sy_call = (sy_call_t *)sys_kldunloadf, .sy_auevent = AUE_MODUNLOAD, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 444 = kldunloadf */
	{ .sy_narg = AS(freebsd64_audit_args), .sy_call = (sy_call_t *)freebsd64_audit, .sy_auevent = AUE_AUDIT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 445 = freebsd64_audit */
	{ .sy_narg = AS(freebsd64_auditon_args), .sy_call = (sy_call_t *)freebsd64_auditon, .sy_auevent = AUE_AUDITON, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 446 = freebsd64_auditon */
	{ .sy_narg = AS(freebsd64_getauid_args), .sy_call = (sy_call_t *)freebsd64_getauid, .sy_auevent = AUE_GETAUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 447 = freebsd64_getauid */
	{ .sy_narg = AS(freebsd64_setauid_args), .sy_call = (sy_call_t *)freebsd64_setauid, .sy_auevent = AUE_SETAUID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 448 = freebsd64_setauid */
	{ .sy_narg = AS(freebsd64_getaudit_args), .sy_call = (sy_call_t *)freebsd64_getaudit, .sy_auevent = AUE_GETAUDIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 449 = freebsd64_getaudit */
	{ .sy_narg = AS(freebsd64_setaudit_args), .sy_call = (sy_call_t *)freebsd64_setaudit, .sy_auevent = AUE_SETAUDIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 450 = freebsd64_setaudit */
	{ .sy_narg = AS(freebsd64_getaudit_addr_args), .sy_call = (sy_call_t *)freebsd64_getaudit_addr, .sy_auevent = AUE_GETAUDIT_ADDR, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 451 = freebsd64_getaudit_addr */
	{ .sy_narg = AS(freebsd64_setaudit_addr_args), .sy_call = (sy_call_t *)freebsd64_setaudit_addr, .sy_auevent = AUE_SETAUDIT_ADDR, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 452 = freebsd64_setaudit_addr */
	{ .sy_narg = AS(freebsd64_auditctl_args), .sy_call = (sy_call_t *)freebsd64_auditctl, .sy_auevent = AUE_AUDITCTL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 453 = freebsd64_auditctl */
	{ .sy_narg = AS(freebsd64__umtx_op_args), .sy_call = (sy_call_t *)freebsd64__umtx_op, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 454 = freebsd64__umtx_op */
	{ .sy_narg = AS(freebsd64_thr_new_args), .sy_call = (sy_call_t *)freebsd64_thr_new, .sy_auevent = AUE_THR_NEW, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 455 = freebsd64_thr_new */
	{ .sy_narg = AS(freebsd64_sigqueue_args), .sy_call = (sy_call_t *)freebsd64_sigqueue, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 456 = freebsd64_sigqueue */
	{ .sy_narg = AS(freebsd64_kmq_open_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 457 = freebsd64_kmq_open */
	{ .sy_narg = AS(freebsd64_kmq_setattr_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_ABSENT },	/* 458 = freebsd64_kmq_setattr */
	{ .sy_narg = AS(freebsd64_kmq_timedreceive_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_ABSENT },	/* 459 = freebsd64_kmq_timedreceive */
	{ .sy_narg = AS(freebsd64_kmq_timedsend_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_ABSENT },	/* 460 = freebsd64_kmq_timedsend */
	{ .sy_narg = AS(freebsd64_kmq_notify_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_ABSENT },	/* 461 = freebsd64_kmq_notify */
	{ .sy_narg = AS(freebsd64_kmq_unlink_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 462 = freebsd64_kmq_unlink */
	{ .sy_narg = AS(freebsd64_abort2_args), .sy_call = (sy_call_t *)freebsd64_abort2, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 463 = freebsd64_abort2 */
	{ .sy_narg = AS(freebsd64_thr_set_name_args), .sy_call = (sy_call_t *)freebsd64_thr_set_name, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 464 = freebsd64_thr_set_name */
	{ .sy_narg = AS(freebsd64_aio_fsync_args), .sy_call = (sy_call_t *)freebsd64_aio_fsync, .sy_auevent = AUE_AIO_FSYNC, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 465 = freebsd64_aio_fsync */
	{ .sy_narg = AS(freebsd64_rtprio_thread_args), .sy_call = (sy_call_t *)freebsd64_rtprio_thread, .sy_auevent = AUE_RTPRIO, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 466 = freebsd64_rtprio_thread */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 467 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 468 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 469 = reserved for local use */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 470 = reserved for local use */
	{ .sy_narg = AS(sctp_peeloff_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_ABSENT },	/* 471 = sctp_peeloff */
	{ .sy_narg = AS(freebsd64_sctp_generic_sendmsg_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_ABSENT },	/* 472 = freebsd64_sctp_generic_sendmsg */
	{ .sy_narg = AS(freebsd64_sctp_generic_sendmsg_iov_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_ABSENT },	/* 473 = freebsd64_sctp_generic_sendmsg_iov */
	{ .sy_narg = AS(freebsd64_sctp_generic_recvmsg_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_ABSENT },	/* 474 = freebsd64_sctp_generic_recvmsg */
	{ .sy_narg = AS(freebsd64_pread_args), .sy_call = (sy_call_t *)freebsd64_pread, .sy_auevent = AUE_PREAD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 475 = freebsd64_pread */
	{ .sy_narg = AS(freebsd64_pwrite_args), .sy_call = (sy_call_t *)freebsd64_pwrite, .sy_auevent = AUE_PWRITE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 476 = freebsd64_pwrite */
	{ .sy_narg = AS(freebsd64_mmap_args), .sy_call = (sy_call_t *)freebsd64_mmap, .sy_auevent = AUE_MMAP, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 477 = freebsd64_mmap */
	{ .sy_narg = AS(lseek_args), .sy_call = (sy_call_t *)sys_lseek, .sy_auevent = AUE_LSEEK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 478 = lseek */
	{ .sy_narg = AS(freebsd64_truncate_args), .sy_call = (sy_call_t *)freebsd64_truncate, .sy_auevent = AUE_TRUNCATE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 479 = freebsd64_truncate */
	{ .sy_narg = AS(ftruncate_args), .sy_call = (sy_call_t *)sys_ftruncate, .sy_auevent = AUE_FTRUNCATE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 480 = ftruncate */
	{ .sy_narg = AS(thr_kill2_args), .sy_call = (sy_call_t *)sys_thr_kill2, .sy_auevent = AUE_THR_KILL2, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 481 = thr_kill2 */
	{ compat12(AS(freebsd12_freebsd64_shm_open_args),freebsd64_shm_open), .sy_auevent = AUE_SHMOPEN, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 482 = freebsd12 freebsd64_shm_open */
	{ .sy_narg = AS(freebsd64_shm_unlink_args), .sy_call = (sy_call_t *)freebsd64_shm_unlink, .sy_auevent = AUE_SHMUNLINK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 483 = freebsd64_shm_unlink */
	{ .sy_narg = AS(freebsd64_cpuset_args), .sy_call = (sy_call_t *)freebsd64_cpuset, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 484 = freebsd64_cpuset */
	{ .sy_narg = AS(cpuset_setid_args), .sy_call = (sy_call_t *)sys_cpuset_setid, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 485 = cpuset_setid */
	{ .sy_narg = AS(freebsd64_cpuset_getid_args), .sy_call = (sy_call_t *)freebsd64_cpuset_getid, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 486 = freebsd64_cpuset_getid */
	{ .sy_narg = AS(freebsd64_cpuset_getaffinity_args), .sy_call = (sy_call_t *)freebsd64_cpuset_getaffinity, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 487 = freebsd64_cpuset_getaffinity */
	{ .sy_narg = AS(freebsd64_cpuset_setaffinity_args), .sy_call = (sy_call_t *)freebsd64_cpuset_setaffinity, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 488 = freebsd64_cpuset_setaffinity */
	{ .sy_narg = AS(freebsd64_faccessat_args), .sy_call = (sy_call_t *)freebsd64_faccessat, .sy_auevent = AUE_FACCESSAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 489 = freebsd64_faccessat */
	{ .sy_narg = AS(freebsd64_fchmodat_args), .sy_call = (sy_call_t *)freebsd64_fchmodat, .sy_auevent = AUE_FCHMODAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 490 = freebsd64_fchmodat */
	{ .sy_narg = AS(freebsd64_fchownat_args), .sy_call = (sy_call_t *)freebsd64_fchownat, .sy_auevent = AUE_FCHOWNAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 491 = freebsd64_fchownat */
	{ .sy_narg = AS(freebsd64_fexecve_args), .sy_call = (sy_call_t *)freebsd64_fexecve, .sy_auevent = AUE_FEXECVE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 492 = freebsd64_fexecve */
	{ compat11(AS(freebsd11_freebsd64_fstatat_args),freebsd64_fstatat), .sy_auevent = AUE_FSTATAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 493 = freebsd11 freebsd64_fstatat */
	{ .sy_narg = AS(freebsd64_futimesat_args), .sy_call = (sy_call_t *)freebsd64_futimesat, .sy_auevent = AUE_FUTIMESAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 494 = freebsd64_futimesat */
	{ .sy_narg = AS(freebsd64_linkat_args), .sy_call = (sy_call_t *)freebsd64_linkat, .sy_auevent = AUE_LINKAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 495 = freebsd64_linkat */
	{ .sy_narg = AS(freebsd64_mkdirat_args), .sy_call = (sy_call_t *)freebsd64_mkdirat, .sy_auevent = AUE_MKDIRAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 496 = freebsd64_mkdirat */
	{ .sy_narg = AS(freebsd64_mkfifoat_args), .sy_call = (sy_call_t *)freebsd64_mkfifoat, .sy_auevent = AUE_MKFIFOAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 497 = freebsd64_mkfifoat */
	{ compat11(AS(freebsd11_freebsd64_mknodat_args),freebsd64_mknodat), .sy_auevent = AUE_MKNODAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 498 = freebsd11 freebsd64_mknodat */
	{ .sy_narg = AS(freebsd64_openat_args), .sy_call = (sy_call_t *)freebsd64_openat, .sy_auevent = AUE_OPENAT_RWTC, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 499 = freebsd64_openat */
	{ .sy_narg = AS(freebsd64_readlinkat_args), .sy_call = (sy_call_t *)freebsd64_readlinkat, .sy_auevent = AUE_READLINKAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 500 = freebsd64_readlinkat */
	{ .sy_narg = AS(freebsd64_renameat_args), .sy_call = (sy_call_t *)freebsd64_renameat, .sy_auevent = AUE_RENAMEAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 501 = freebsd64_renameat */
	{ .sy_narg = AS(freebsd64_symlinkat_args), .sy_call = (sy_call_t *)freebsd64_symlinkat, .sy_auevent = AUE_SYMLINKAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 502 = freebsd64_symlinkat */
	{ .sy_narg = AS(freebsd64_unlinkat_args), .sy_call = (sy_call_t *)freebsd64_unlinkat, .sy_auevent = AUE_UNLINKAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 503 = freebsd64_unlinkat */
	{ .sy_narg = AS(posix_openpt_args), .sy_call = (sy_call_t *)sys_posix_openpt, .sy_auevent = AUE_POSIX_OPENPT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 504 = posix_openpt */
	{ .sy_narg = AS(freebsd64_gssd_syscall_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 505 = freebsd64_gssd_syscall */
	{ .sy_narg = AS(freebsd64_jail_get_args), .sy_call = (sy_call_t *)freebsd64_jail_get, .sy_auevent = AUE_JAIL_GET, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 506 = freebsd64_jail_get */
	{ .sy_narg = AS(freebsd64_jail_set_args), .sy_call = (sy_call_t *)freebsd64_jail_set, .sy_auevent = AUE_JAIL_SET, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 507 = freebsd64_jail_set */
	{ .sy_narg = AS(jail_remove_args), .sy_call = (sy_call_t *)sys_jail_remove, .sy_auevent = AUE_JAIL_REMOVE, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 508 = jail_remove */
	{ compat12(AS(freebsd12_closefrom_args),closefrom), .sy_auevent = AUE_CLOSEFROM, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 509 = freebsd12 closefrom */
	{ .sy_narg = AS(freebsd64___semctl_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 510 = freebsd64___semctl */
	{ .sy_narg = AS(freebsd64_msgctl_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 511 = freebsd64_msgctl */
	{ .sy_narg = AS(freebsd64_shmctl_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 512 = freebsd64_shmctl */
	{ .sy_narg = AS(freebsd64_lpathconf_args), .sy_call = (sy_call_t *)freebsd64_lpathconf, .sy_auevent = AUE_LPATHCONF, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 513 = freebsd64_lpathconf */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 514 = obsolete cap_new */
	{ .sy_narg = AS(freebsd64___cap_rights_get_args), .sy_call = (sy_call_t *)freebsd64___cap_rights_get, .sy_auevent = AUE_CAP_RIGHTS_GET, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 515 = freebsd64___cap_rights_get */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_cap_enter, .sy_auevent = AUE_CAP_ENTER, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 516 = cap_enter */
	{ .sy_narg = AS(freebsd64_cap_getmode_args), .sy_call = (sy_call_t *)freebsd64_cap_getmode, .sy_auevent = AUE_CAP_GETMODE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 517 = freebsd64_cap_getmode */
	{ .sy_narg = AS(freebsd64_pdfork_args), .sy_call = (sy_call_t *)freebsd64_pdfork, .sy_auevent = AUE_PDFORK, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 518 = freebsd64_pdfork */
	{ .sy_narg = AS(pdkill_args), .sy_call = (sy_call_t *)sys_pdkill, .sy_auevent = AUE_PDKILL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 519 = pdkill */
	{ .sy_narg = AS(freebsd64_pdgetpid_args), .sy_call = (sy_call_t *)freebsd64_pdgetpid, .sy_auevent = AUE_PDGETPID, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 520 = freebsd64_pdgetpid */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 521 = reserved for local use */
	{ .sy_narg = AS(freebsd64_pselect_args), .sy_call = (sy_call_t *)freebsd64_pselect, .sy_auevent = AUE_SELECT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 522 = freebsd64_pselect */
	{ .sy_narg = AS(freebsd64_getloginclass_args), .sy_call = (sy_call_t *)freebsd64_getloginclass, .sy_auevent = AUE_GETLOGINCLASS, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 523 = freebsd64_getloginclass */
	{ .sy_narg = AS(freebsd64_setloginclass_args), .sy_call = (sy_call_t *)freebsd64_setloginclass, .sy_auevent = AUE_SETLOGINCLASS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 524 = freebsd64_setloginclass */
	{ .sy_narg = AS(freebsd64_rctl_get_racct_args), .sy_call = (sy_call_t *)freebsd64_rctl_get_racct, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 525 = freebsd64_rctl_get_racct */
	{ .sy_narg = AS(freebsd64_rctl_get_rules_args), .sy_call = (sy_call_t *)freebsd64_rctl_get_rules, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 526 = freebsd64_rctl_get_rules */
	{ .sy_narg = AS(freebsd64_rctl_get_limits_args), .sy_call = (sy_call_t *)freebsd64_rctl_get_limits, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 527 = freebsd64_rctl_get_limits */
	{ .sy_narg = AS(freebsd64_rctl_add_rule_args), .sy_call = (sy_call_t *)freebsd64_rctl_add_rule, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 528 = freebsd64_rctl_add_rule */
	{ .sy_narg = AS(freebsd64_rctl_remove_rule_args), .sy_call = (sy_call_t *)freebsd64_rctl_remove_rule, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 529 = freebsd64_rctl_remove_rule */
	{ .sy_narg = AS(posix_fallocate_args), .sy_call = (sy_call_t *)sys_posix_fallocate, .sy_auevent = AUE_POSIX_FALLOCATE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 530 = posix_fallocate */
	{ .sy_narg = AS(posix_fadvise_args), .sy_call = (sy_call_t *)sys_posix_fadvise, .sy_auevent = AUE_POSIX_FADVISE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 531 = posix_fadvise */
	{ .sy_narg = AS(freebsd64_wait6_args), .sy_call = (sy_call_t *)freebsd64_wait6, .sy_auevent = AUE_WAIT6, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 532 = freebsd64_wait6 */
	{ .sy_narg = AS(freebsd64_cap_rights_limit_args), .sy_call = (sy_call_t *)freebsd64_cap_rights_limit, .sy_auevent = AUE_CAP_RIGHTS_LIMIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 533 = freebsd64_cap_rights_limit */
	{ .sy_narg = AS(freebsd64_cap_ioctls_limit_args), .sy_call = (sy_call_t *)freebsd64_cap_ioctls_limit, .sy_auevent = AUE_CAP_IOCTLS_LIMIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 534 = freebsd64_cap_ioctls_limit */
	{ .sy_narg = AS(freebsd64_cap_ioctls_get_args), .sy_call = (sy_call_t *)freebsd64_cap_ioctls_get, .sy_auevent = AUE_CAP_IOCTLS_GET, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 535 = freebsd64_cap_ioctls_get */
	{ .sy_narg = AS(cap_fcntls_limit_args), .sy_call = (sy_call_t *)sys_cap_fcntls_limit, .sy_auevent = AUE_CAP_FCNTLS_LIMIT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 536 = cap_fcntls_limit */
	{ .sy_narg = AS(freebsd64_cap_fcntls_get_args), .sy_call = (sy_call_t *)freebsd64_cap_fcntls_get, .sy_auevent = AUE_CAP_FCNTLS_GET, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 537 = freebsd64_cap_fcntls_get */
	{ .sy_narg = AS(freebsd64_bindat_args), .sy_call = (sy_call_t *)freebsd64_bindat, .sy_auevent = AUE_BINDAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 538 = freebsd64_bindat */
	{ .sy_narg = AS(freebsd64_connectat_args), .sy_call = (sy_call_t *)freebsd64_connectat, .sy_auevent = AUE_CONNECTAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 539 = freebsd64_connectat */
	{ .sy_narg = AS(freebsd64_chflagsat_args), .sy_call = (sy_call_t *)freebsd64_chflagsat, .sy_auevent = AUE_CHFLAGSAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 540 = freebsd64_chflagsat */
	{ .sy_narg = AS(freebsd64_accept4_args), .sy_call = (sy_call_t *)freebsd64_accept4, .sy_auevent = AUE_ACCEPT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 541 = freebsd64_accept4 */
	{ .sy_narg = AS(freebsd64_pipe2_args), .sy_call = (sy_call_t *)freebsd64_pipe2, .sy_auevent = AUE_PIPE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 542 = freebsd64_pipe2 */
	{ .sy_narg = AS(freebsd64_aio_mlock_args), .sy_call = (sy_call_t *)freebsd64_aio_mlock, .sy_auevent = AUE_AIO_MLOCK, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 543 = freebsd64_aio_mlock */
	{ .sy_narg = AS(freebsd64_procctl_args), .sy_call = (sy_call_t *)freebsd64_procctl, .sy_auevent = AUE_PROCCTL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 544 = freebsd64_procctl */
	{ .sy_narg = AS(freebsd64_ppoll_args), .sy_call = (sy_call_t *)freebsd64_ppoll, .sy_auevent = AUE_POLL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 545 = freebsd64_ppoll */
	{ .sy_narg = AS(freebsd64_futimens_args), .sy_call = (sy_call_t *)freebsd64_futimens, .sy_auevent = AUE_FUTIMES, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 546 = freebsd64_futimens */
	{ .sy_narg = AS(freebsd64_utimensat_args), .sy_call = (sy_call_t *)freebsd64_utimensat, .sy_auevent = AUE_FUTIMESAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 547 = freebsd64_utimensat */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 548 = cocall_slow */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)nosys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },			/* 549 = coaccept_slow */
	{ .sy_narg = AS(fdatasync_args), .sy_call = (sy_call_t *)sys_fdatasync, .sy_auevent = AUE_FSYNC, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 550 = fdatasync */
	{ .sy_narg = AS(freebsd64_fstat_args), .sy_call = (sy_call_t *)freebsd64_fstat, .sy_auevent = AUE_FSTAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 551 = freebsd64_fstat */
	{ .sy_narg = AS(freebsd64_fstatat_args), .sy_call = (sy_call_t *)freebsd64_fstatat, .sy_auevent = AUE_FSTATAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 552 = freebsd64_fstatat */
	{ .sy_narg = AS(freebsd64_fhstat_args), .sy_call = (sy_call_t *)freebsd64_fhstat, .sy_auevent = AUE_FHSTAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 553 = freebsd64_fhstat */
	{ .sy_narg = AS(freebsd64_getdirentries_args), .sy_call = (sy_call_t *)freebsd64_getdirentries, .sy_auevent = AUE_GETDIRENTRIES, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 554 = freebsd64_getdirentries */
	{ .sy_narg = AS(freebsd64_statfs_args), .sy_call = (sy_call_t *)freebsd64_statfs, .sy_auevent = AUE_STATFS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 555 = freebsd64_statfs */
	{ .sy_narg = AS(freebsd64_fstatfs_args), .sy_call = (sy_call_t *)freebsd64_fstatfs, .sy_auevent = AUE_FSTATFS, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 556 = freebsd64_fstatfs */
	{ .sy_narg = AS(freebsd64_getfsstat_args), .sy_call = (sy_call_t *)freebsd64_getfsstat, .sy_auevent = AUE_GETFSSTAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 557 = freebsd64_getfsstat */
	{ .sy_narg = AS(freebsd64_fhstatfs_args), .sy_call = (sy_call_t *)freebsd64_fhstatfs, .sy_auevent = AUE_FHSTATFS, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 558 = freebsd64_fhstatfs */
	{ .sy_narg = AS(freebsd64_mknodat_args), .sy_call = (sy_call_t *)freebsd64_mknodat, .sy_auevent = AUE_MKNODAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 559 = freebsd64_mknodat */
	{ .sy_narg = AS(freebsd64_kevent_args), .sy_call = (sy_call_t *)freebsd64_kevent, .sy_auevent = AUE_KEVENT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 560 = freebsd64_kevent */
	{ .sy_narg = AS(freebsd64_cpuset_getdomain_args), .sy_call = (sy_call_t *)freebsd64_cpuset_getdomain, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 561 = freebsd64_cpuset_getdomain */
	{ .sy_narg = AS(freebsd64_cpuset_setdomain_args), .sy_call = (sy_call_t *)freebsd64_cpuset_setdomain, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 562 = freebsd64_cpuset_setdomain */
	{ .sy_narg = AS(freebsd64_getrandom_args), .sy_call = (sy_call_t *)freebsd64_getrandom, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 563 = freebsd64_getrandom */
	{ .sy_narg = AS(freebsd64_getfhat_args), .sy_call = (sy_call_t *)freebsd64_getfhat, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 564 = freebsd64_getfhat */
	{ .sy_narg = AS(freebsd64_fhlink_args), .sy_call = (sy_call_t *)freebsd64_fhlink, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 565 = freebsd64_fhlink */
	{ .sy_narg = AS(freebsd64_fhlinkat_args), .sy_call = (sy_call_t *)freebsd64_fhlinkat, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 566 = freebsd64_fhlinkat */
	{ .sy_narg = AS(freebsd64_fhreadlink_args), .sy_call = (sy_call_t *)freebsd64_fhreadlink, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 567 = freebsd64_fhreadlink */
	{ .sy_narg = AS(freebsd64_funlinkat_args), .sy_call = (sy_call_t *)freebsd64_funlinkat, .sy_auevent = AUE_UNLINKAT, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 568 = freebsd64_funlinkat */
	{ .sy_narg = AS(freebsd64_copy_file_range_args), .sy_call = (sy_call_t *)freebsd64_copy_file_range, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 569 = freebsd64_copy_file_range */
	{ .sy_narg = AS(freebsd64___sysctlbyname_args), .sy_call = (sy_call_t *)freebsd64___sysctlbyname, .sy_auevent = AUE_SYSCTL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 570 = freebsd64___sysctlbyname */
	{ .sy_narg = AS(freebsd64_shm_open2_args), .sy_call = (sy_call_t *)freebsd64_shm_open2, .sy_auevent = AUE_SHMOPEN, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 571 = freebsd64_shm_open2 */
	{ .sy_narg = AS(freebsd64_shm_rename_args), .sy_call = (sy_call_t *)freebsd64_shm_rename, .sy_auevent = AUE_SHMRENAME, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 572 = freebsd64_shm_rename */
	{ .sy_narg = AS(freebsd64_sigfastblock_args), .sy_call = (sy_call_t *)freebsd64_sigfastblock, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 573 = freebsd64_sigfastblock */
	{ .sy_narg = AS(freebsd64___realpathat_args), .sy_call = (sy_call_t *)freebsd64___realpathat, .sy_auevent = AUE_REALPATHAT, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 574 = freebsd64___realpathat */
	{ .sy_narg = AS(close_range_args), .sy_call = (sy_call_t *)sys_close_range, .sy_auevent = AUE_CLOSERANGE, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 575 = close_range */
	{ .sy_narg = AS(freebsd64_rpctls_syscall_args), .sy_call = (sy_call_t *)lkmressys, .sy_auevent = AUE_NULL, .sy_flags = 0, .sy_thrcnt = SY_THR_ABSENT },	/* 576 = freebsd64_rpctls_syscall */
	{ .sy_narg = AS(freebsd64___specialfd_args), .sy_call = (sy_call_t *)freebsd64___specialfd, .sy_auevent = AUE_SPECIALFD, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 577 = freebsd64___specialfd */
	{ .sy_narg = AS(freebsd64_aio_writev_args), .sy_call = (sy_call_t *)freebsd64_aio_writev, .sy_auevent = AUE_AIO_WRITEV, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 578 = freebsd64_aio_writev */
	{ .sy_narg = AS(freebsd64_aio_readv_args), .sy_call = (sy_call_t *)freebsd64_aio_readv, .sy_auevent = AUE_AIO_READV, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 579 = freebsd64_aio_readv */
	{ .sy_narg = AS(freebsd64_fspacectl_args), .sy_call = (sy_call_t *)freebsd64_fspacectl, .sy_auevent = AUE_FSPACECTL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 580 = freebsd64_fspacectl */
	{ .sy_narg = 0, .sy_call = (sy_call_t *)sys_sched_getcpu, .sy_auevent = AUE_NULL, .sy_flags = SYF_CAPENABLED, .sy_thrcnt = SY_THR_STATIC },	/* 581 = sched_getcpu */
	{ .sy_narg = AS(freebsd64_swapoff_args), .sy_call = (sy_call_t *)freebsd64_swapoff, .sy_auevent = AUE_SWAPOFF, .sy_flags = 0, .sy_thrcnt = SY_THR_STATIC },	/* 582 = freebsd64_swapoff */
};
