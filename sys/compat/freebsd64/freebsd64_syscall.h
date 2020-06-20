/*
 * System call numbers.
 *
 * DO NOT EDIT-- this file is automatically @generated.
 * $FreeBSD$
 */

#define	FREEBSD64_SYS_syscall	0
#define	FREEBSD64_SYS_exit	1
#define	FREEBSD64_SYS_fork	2
#define	FREEBSD64_SYS_freebsd64_read	3
#define	FREEBSD64_SYS_freebsd64_write	4
#define	FREEBSD64_SYS_freebsd64_open	5
#define	FREEBSD64_SYS_close	6
#define	FREEBSD64_SYS_freebsd64_wait4	7
				/* 8 is obsolete ocreat */
#define	FREEBSD64_SYS_freebsd64_link	9
#define	FREEBSD64_SYS_freebsd64_unlink	10
				/* 11 is obsolete execv */
#define	FREEBSD64_SYS_freebsd64_chdir	12
#define	FREEBSD64_SYS_fchdir	13
#define	FREEBSD64_SYS_freebsd11_freebsd64_mknod	14
#define	FREEBSD64_SYS_freebsd64_chmod	15
#define	FREEBSD64_SYS_freebsd64_chown	16
#define	FREEBSD64_SYS_freebsd64_break	17
				/* 18 is obsolete freebsd4_getfsstat */
				/* 19 is obsolete olseek */
#define	FREEBSD64_SYS_getpid	20
#define	FREEBSD64_SYS_freebsd64_mount	21
#define	FREEBSD64_SYS_freebsd64_unmount	22
#define	FREEBSD64_SYS_setuid	23
#define	FREEBSD64_SYS_getuid	24
#define	FREEBSD64_SYS_geteuid	25
#define	FREEBSD64_SYS_freebsd64_ptrace	26
#define	FREEBSD64_SYS_freebsd64_recvmsg	27
#define	FREEBSD64_SYS_freebsd64_sendmsg	28
#define	FREEBSD64_SYS_freebsd64_recvfrom	29
#define	FREEBSD64_SYS_freebsd64_accept	30
#define	FREEBSD64_SYS_freebsd64_getpeername	31
#define	FREEBSD64_SYS_freebsd64_getsockname	32
#define	FREEBSD64_SYS_freebsd64_access	33
#define	FREEBSD64_SYS_freebsd64_chflags	34
#define	FREEBSD64_SYS_fchflags	35
#define	FREEBSD64_SYS_sync	36
#define	FREEBSD64_SYS_kill	37
				/* 38 is obsolete ostat */
#define	FREEBSD64_SYS_getppid	39
				/* 40 is obsolete olstat */
#define	FREEBSD64_SYS_dup	41
#define	FREEBSD64_SYS_freebsd10_pipe	42
#define	FREEBSD64_SYS_getegid	43
#define	FREEBSD64_SYS_freebsd64_profil	44
#define	FREEBSD64_SYS_freebsd64_ktrace	45
				/* 46 is obsolete osigaction */
#define	FREEBSD64_SYS_getgid	47
				/* 48 is obsolete osigprocmask */
#define	FREEBSD64_SYS_freebsd64_getlogin	49
#define	FREEBSD64_SYS_freebsd64_setlogin	50
#define	FREEBSD64_SYS_freebsd64_acct	51
				/* 52 is obsolete osigpending */
#define	FREEBSD64_SYS_freebsd64_sigaltstack	53
#define	FREEBSD64_SYS_freebsd64_ioctl	54
#define	FREEBSD64_SYS_reboot	55
#define	FREEBSD64_SYS_freebsd64_revoke	56
#define	FREEBSD64_SYS_freebsd64_symlink	57
#define	FREEBSD64_SYS_freebsd64_readlink	58
#define	FREEBSD64_SYS_freebsd64_execve	59
#define	FREEBSD64_SYS_umask	60
#define	FREEBSD64_SYS_freebsd64_chroot	61
				/* 62 is obsolete ofstat */
				/* 63 is obsolete ogetkerninfo */
				/* 64 is obsolete ogetpagesize */
#define	FREEBSD64_SYS_freebsd64_msync	65
#define	FREEBSD64_SYS_vfork	66
				/* 67 is obsolete vread */
				/* 68 is obsolete vwrite */
#define	FREEBSD64_SYS_sbrk	69
#define	FREEBSD64_SYS_sstk	70
				/* 71 is obsolete ommap */
#define	FREEBSD64_SYS_freebsd11_vadvise	72
#define	FREEBSD64_SYS_freebsd64_munmap	73
#define	FREEBSD64_SYS_freebsd64_mprotect	74
#define	FREEBSD64_SYS_freebsd64_madvise	75
				/* 76 is obsolete vhangup */
				/* 77 is obsolete vlimit */
#define	FREEBSD64_SYS_freebsd64_mincore	78
#define	FREEBSD64_SYS_freebsd64_getgroups	79
#define	FREEBSD64_SYS_freebsd64_setgroups	80
#define	FREEBSD64_SYS_getpgrp	81
#define	FREEBSD64_SYS_setpgid	82
#define	FREEBSD64_SYS_freebsd64_setitimer	83
				/* 84 is obsolete owait */
#define	FREEBSD64_SYS_freebsd64_swapon	85
#define	FREEBSD64_SYS_freebsd64_getitimer	86
				/* 87 is obsolete ogethostname */
				/* 88 is obsolete osethostname */
#define	FREEBSD64_SYS_getdtablesize	89
#define	FREEBSD64_SYS_dup2	90
#define	FREEBSD64_SYS_freebsd64_fcntl	92
#define	FREEBSD64_SYS_freebsd64_select	93
#define	FREEBSD64_SYS_fsync	95
#define	FREEBSD64_SYS_setpriority	96
#define	FREEBSD64_SYS_socket	97
#define	FREEBSD64_SYS_freebsd64_connect	98
				/* 99 is obsolete oaccept */
#define	FREEBSD64_SYS_getpriority	100
				/* 101 is obsolete osend */
				/* 102 is obsolete orecv */
				/* 103 is obsolete osigreturn */
#define	FREEBSD64_SYS_freebsd64_bind	104
#define	FREEBSD64_SYS_freebsd64_setsockopt	105
#define	FREEBSD64_SYS_listen	106
				/* 107 is obsolete vtimes */
				/* 108 is obsolete osigvec */
				/* 109 is obsolete osigblock */
				/* 110 is obsolete osigsetmask */
				/* 111 is obsolete osigsuspend */
				/* 112 is obsolete osigstack */
				/* 113 is obsolete orecvmsg */
				/* 114 is obsolete osendmsg */
				/* 115 is obsolete vtrace */
#define	FREEBSD64_SYS_freebsd64_gettimeofday	116
#define	FREEBSD64_SYS_freebsd64_getrusage	117
#define	FREEBSD64_SYS_freebsd64_getsockopt	118
#define	FREEBSD64_SYS_freebsd64_readv	120
#define	FREEBSD64_SYS_freebsd64_writev	121
#define	FREEBSD64_SYS_freebsd64_settimeofday	122
#define	FREEBSD64_SYS_fchown	123
#define	FREEBSD64_SYS_fchmod	124
				/* 125 is obsolete orecvfrom */
#define	FREEBSD64_SYS_setreuid	126
#define	FREEBSD64_SYS_setregid	127
#define	FREEBSD64_SYS_freebsd64_rename	128
				/* 129 is obsolete otruncate */
				/* 130 is obsolete oftruncate */
#define	FREEBSD64_SYS_flock	131
#define	FREEBSD64_SYS_freebsd64_mkfifo	132
#define	FREEBSD64_SYS_freebsd64_sendto	133
#define	FREEBSD64_SYS_shutdown	134
#define	FREEBSD64_SYS_freebsd64_socketpair	135
#define	FREEBSD64_SYS_freebsd64_mkdir	136
#define	FREEBSD64_SYS_freebsd64_rmdir	137
#define	FREEBSD64_SYS_freebsd64_utimes	138
				/* 139 is obsolete 4.2 sigreturn */
#define	FREEBSD64_SYS_freebsd64_adjtime	140
				/* 141 is obsolete ogetpeername */
				/* 142 is obsolete ogethostid */
				/* 143 is obsolete osethostid */
				/* 144 is obsolete ogetrlimit */
				/* 145 is obsolete osetrlimit */
				/* 146 is obsolete okillpg */
#define	FREEBSD64_SYS_setsid	147
#define	FREEBSD64_SYS_freebsd64_quotactl	148
				/* 149 is obsolete oquota */
				/* 150 is obsolete ogetsockname */
#define	FREEBSD64_SYS_freebsd64_nlm_syscall	154
#define	FREEBSD64_SYS_freebsd64_nfssvc	155
				/* 156 is obsolete ogetdirentries */
				/* 157 is obsolete freebsd4_statfs */
				/* 158 is obsolete freebsd4_fstatfs */
#define	FREEBSD64_SYS_freebsd64_lgetfh	160
#define	FREEBSD64_SYS_freebsd64_getfh	161
				/* 162 is obsolete freebsd4_getdomainname */
				/* 163 is obsolete freebsd4_setdomainname */
				/* 164 is obsolete freebsd4_uname */
#define	FREEBSD64_SYS_freebsd64_sysarch	165
#define	FREEBSD64_SYS_freebsd64_rtprio	166
#define	FREEBSD64_SYS_freebsd64_semsys	169
#define	FREEBSD64_SYS_freebsd64_msgsys	170
#define	FREEBSD64_SYS_freebsd64_shmsys	171
				/* 173 is freebsd6 freebsd64_pread */
				/* 174 is freebsd6 freebsd64_pwrite */
#define	FREEBSD64_SYS_setfib	175
#define	FREEBSD64_SYS_freebsd64_ntp_adjtime	176
#define	FREEBSD64_SYS_setgid	181
#define	FREEBSD64_SYS_setegid	182
#define	FREEBSD64_SYS_seteuid	183
				/* 184 is obsolete lfs_bmapv */
				/* 185 is obsolete lfs_markv */
				/* 186 is obsolete lfs_segclean */
				/* 187 is obsolete lfs_segwait */
#define	FREEBSD64_SYS_freebsd11_freebsd64_stat	188
#define	FREEBSD64_SYS_freebsd11_freebsd64_fstat	189
#define	FREEBSD64_SYS_freebsd11_freebsd64_lstat	190
#define	FREEBSD64_SYS_freebsd64_pathconf	191
#define	FREEBSD64_SYS_fpathconf	192
#define	FREEBSD64_SYS_freebsd64_getrlimit	194
#define	FREEBSD64_SYS_freebsd64_setrlimit	195
#define	FREEBSD64_SYS_freebsd11_freebsd64_getdirentries	196
				/* 197 is freebsd6 freebsd64_mmap */
#define	FREEBSD64_SYS___syscall	198
				/* 199 is freebsd6 lseek */
				/* 200 is freebsd6 freebsd64_truncate */
				/* 201 is freebsd6 ftruncate */
#define	FREEBSD64_SYS_freebsd64___sysctl	202
#define	FREEBSD64_SYS_freebsd64_mlock	203
#define	FREEBSD64_SYS_freebsd64_munlock	204
#define	FREEBSD64_SYS_freebsd64_undelete	205
#define	FREEBSD64_SYS_freebsd64_futimes	206
#define	FREEBSD64_SYS_getpgid	207
#define	FREEBSD64_SYS_freebsd64_poll	209
#define	FREEBSD64_SYS_freebsd7_freebsd64___semctl	220
#define	FREEBSD64_SYS_semget	221
#define	FREEBSD64_SYS_freebsd64_semop	222
				/* 223 is obsolete semconfig */
#define	FREEBSD64_SYS_freebsd7_freebsd64_msgctl	224
#define	FREEBSD64_SYS_msgget	225
#define	FREEBSD64_SYS_freebsd64_msgsnd	226
#define	FREEBSD64_SYS_freebsd64_msgrcv	227
#define	FREEBSD64_SYS_freebsd64_shmat	228
#define	FREEBSD64_SYS_freebsd7_freebsd64_shmctl	229
#define	FREEBSD64_SYS_freebsd64_shmdt	230
#define	FREEBSD64_SYS_shmget	231
#define	FREEBSD64_SYS_freebsd64_clock_gettime	232
#define	FREEBSD64_SYS_freebsd64_clock_settime	233
#define	FREEBSD64_SYS_freebsd64_clock_getres	234
#define	FREEBSD64_SYS_freebsd64_ktimer_create	235
#define	FREEBSD64_SYS_ktimer_delete	236
#define	FREEBSD64_SYS_freebsd64_ktimer_settime	237
#define	FREEBSD64_SYS_freebsd64_ktimer_gettime	238
#define	FREEBSD64_SYS_ktimer_getoverrun	239
#define	FREEBSD64_SYS_freebsd64_nanosleep	240
#define	FREEBSD64_SYS_freebsd64_ffclock_getcounter	241
#define	FREEBSD64_SYS_freebsd64_ffclock_setestimate	242
#define	FREEBSD64_SYS_freebsd64_ffclock_getestimate	243
#define	FREEBSD64_SYS_freebsd64_clock_nanosleep	244
#define	FREEBSD64_SYS_freebsd64_clock_getcpuclockid2	247
#define	FREEBSD64_SYS_freebsd64_ntp_gettime	248
#define	FREEBSD64_SYS_freebsd64_minherit	250
#define	FREEBSD64_SYS_rfork	251
				/* 252 is obsolete openbsd_poll */
#define	FREEBSD64_SYS_issetugid	253
#define	FREEBSD64_SYS_freebsd64_lchown	254
#define	FREEBSD64_SYS_freebsd64_aio_read	255
#define	FREEBSD64_SYS_freebsd64_aio_write	256
#define	FREEBSD64_SYS_freebsd64_lio_listio	257
#define	FREEBSD64_SYS_freebsd64_kbounce	258
#define	FREEBSD64_SYS_freebsd64_flag_captured	259
#define	FREEBSD64_SYS_freebsd11_freebsd64_getdents	272
#define	FREEBSD64_SYS_freebsd64_lchmod	274
				/* 275 is obsolete netbsd_lchown */
#define	FREEBSD64_SYS_freebsd64_lutimes	276
				/* 277 is obsolete netbsd_msync */
#define	FREEBSD64_SYS_freebsd11_freebsd64_nstat	278
#define	FREEBSD64_SYS_freebsd11_freebsd64_nfstat	279
#define	FREEBSD64_SYS_freebsd11_freebsd64_nlstat	280
#define	FREEBSD64_SYS_freebsd64_preadv	289
#define	FREEBSD64_SYS_freebsd64_pwritev	290
				/* 297 is obsolete freebsd4_fhstatfs */
#define	FREEBSD64_SYS_freebsd64_fhopen	298
#define	FREEBSD64_SYS_freebsd11_freebsd64_fhstat	299
#define	FREEBSD64_SYS_modnext	300
#define	FREEBSD64_SYS_freebsd64_modstat	301
#define	FREEBSD64_SYS_modfnext	302
#define	FREEBSD64_SYS_freebsd64_modfind	303
#define	FREEBSD64_SYS_freebsd64_kldload	304
#define	FREEBSD64_SYS_kldunload	305
#define	FREEBSD64_SYS_freebsd64_kldfind	306
#define	FREEBSD64_SYS_kldnext	307
#define	FREEBSD64_SYS_freebsd64_kldstat	308
#define	FREEBSD64_SYS_kldfirstmod	309
#define	FREEBSD64_SYS_getsid	310
#define	FREEBSD64_SYS_setresuid	311
#define	FREEBSD64_SYS_setresgid	312
				/* 313 is obsolete signanosleep */
#define	FREEBSD64_SYS_freebsd64_aio_return	314
#define	FREEBSD64_SYS_freebsd64_aio_suspend	315
#define	FREEBSD64_SYS_freebsd64_aio_cancel	316
#define	FREEBSD64_SYS_freebsd64_aio_error	317
				/* 318 is freebsd6 freebsd64_aio_read */
				/* 319 is freebsd6 freebsd64_aio_write */
				/* 320 is freebsd6 freebsd64_lio_listio */
#define	FREEBSD64_SYS_yield	321
				/* 322 is obsolete thr_sleep */
				/* 323 is obsolete thr_wakeup */
#define	FREEBSD64_SYS_mlockall	324
#define	FREEBSD64_SYS_munlockall	325
#define	FREEBSD64_SYS_freebsd64___getcwd	326
#define	FREEBSD64_SYS_freebsd64_sched_setparam	327
#define	FREEBSD64_SYS_freebsd64_sched_getparam	328
#define	FREEBSD64_SYS_freebsd64_sched_setscheduler	329
#define	FREEBSD64_SYS_sched_getscheduler	330
#define	FREEBSD64_SYS_sched_yield	331
#define	FREEBSD64_SYS_sched_get_priority_max	332
#define	FREEBSD64_SYS_sched_get_priority_min	333
#define	FREEBSD64_SYS_freebsd64_sched_rr_get_interval	334
#define	FREEBSD64_SYS_freebsd64_utrace	335
				/* 336 is obsolete freebsd4_sendfile */
#define	FREEBSD64_SYS_freebsd64_kldsym	337
#define	FREEBSD64_SYS_freebsd64_jail	338
#define	FREEBSD64_SYS_freebsd64_nnpfs_syscall	339
#define	FREEBSD64_SYS_freebsd64_sigprocmask	340
#define	FREEBSD64_SYS_freebsd64_sigsuspend	341
				/* 342 is obsolete freebsd4_sigaction */
#define	FREEBSD64_SYS_freebsd64_sigpending	343
				/* 344 is obsolete freebsd4_sigreturn */
#define	FREEBSD64_SYS_freebsd64_sigtimedwait	345
#define	FREEBSD64_SYS_freebsd64_sigwaitinfo	346
#define	FREEBSD64_SYS_freebsd64___acl_get_file	347
#define	FREEBSD64_SYS_freebsd64___acl_set_file	348
#define	FREEBSD64_SYS_freebsd64___acl_get_fd	349
#define	FREEBSD64_SYS_freebsd64___acl_set_fd	350
#define	FREEBSD64_SYS_freebsd64___acl_delete_file	351
#define	FREEBSD64_SYS___acl_delete_fd	352
#define	FREEBSD64_SYS_freebsd64___acl_aclcheck_file	353
#define	FREEBSD64_SYS_freebsd64___acl_aclcheck_fd	354
#define	FREEBSD64_SYS_freebsd64_extattrctl	355
#define	FREEBSD64_SYS_freebsd64_extattr_set_file	356
#define	FREEBSD64_SYS_freebsd64_extattr_get_file	357
#define	FREEBSD64_SYS_freebsd64_extattr_delete_file	358
#define	FREEBSD64_SYS_freebsd64_aio_waitcomplete	359
#define	FREEBSD64_SYS_freebsd64_getresuid	360
#define	FREEBSD64_SYS_freebsd64_getresgid	361
#define	FREEBSD64_SYS_kqueue	362
#define	FREEBSD64_SYS_freebsd11_freebsd64_kevent	363
				/* 364 is obsolete __cap_get_proc */
				/* 365 is obsolete __cap_set_proc */
				/* 366 is obsolete __cap_get_fd */
				/* 367 is obsolete __cap_get_file */
				/* 368 is obsolete __cap_set_fd */
				/* 369 is obsolete __cap_set_file */
#define	FREEBSD64_SYS_freebsd64_extattr_set_fd	371
#define	FREEBSD64_SYS_freebsd64_extattr_get_fd	372
#define	FREEBSD64_SYS_freebsd64_extattr_delete_fd	373
#define	FREEBSD64_SYS___setugid	374
				/* 375 is obsolete nfsclnt */
#define	FREEBSD64_SYS_freebsd64_eaccess	376
#define	FREEBSD64_SYS_afs3_syscall	377
#define	FREEBSD64_SYS_freebsd64_nmount	378
				/* 379 is obsolete kse_exit */
				/* 380 is obsolete kse_wakeup */
				/* 381 is obsolete kse_create */
				/* 382 is obsolete kse_thr_interrupt */
				/* 383 is obsolete kse_release */
#define	FREEBSD64_SYS_freebsd64___mac_get_proc	384
#define	FREEBSD64_SYS_freebsd64___mac_set_proc	385
#define	FREEBSD64_SYS_freebsd64___mac_get_fd	386
#define	FREEBSD64_SYS_freebsd64___mac_get_file	387
#define	FREEBSD64_SYS_freebsd64___mac_set_fd	388
#define	FREEBSD64_SYS_freebsd64___mac_set_file	389
#define	FREEBSD64_SYS_freebsd64_kenv	390
#define	FREEBSD64_SYS_freebsd64_lchflags	391
#define	FREEBSD64_SYS_freebsd64_uuidgen	392
#define	FREEBSD64_SYS_freebsd64_sendfile	393
#define	FREEBSD64_SYS_freebsd64_mac_syscall	394
#define	FREEBSD64_SYS_freebsd11_freebsd64_getfsstat	395
#define	FREEBSD64_SYS_freebsd11_freebsd64_statfs	396
#define	FREEBSD64_SYS_freebsd11_freebsd64_fstatfs	397
#define	FREEBSD64_SYS_freebsd11_freebsd64_fhstatfs	398
#define	FREEBSD64_SYS_ksem_close	400
#define	FREEBSD64_SYS_ksem_post	401
#define	FREEBSD64_SYS_ksem_wait	402
#define	FREEBSD64_SYS_ksem_trywait	403
#define	FREEBSD64_SYS_freebsd64_ksem_init	404
#define	FREEBSD64_SYS_freebsd64_ksem_open	405
#define	FREEBSD64_SYS_freebsd64_ksem_unlink	406
#define	FREEBSD64_SYS_freebsd64_ksem_getvalue	407
#define	FREEBSD64_SYS_ksem_destroy	408
#define	FREEBSD64_SYS_freebsd64___mac_get_pid	409
#define	FREEBSD64_SYS_freebsd64___mac_get_link	410
#define	FREEBSD64_SYS_freebsd64___mac_set_link	411
#define	FREEBSD64_SYS_freebsd64_extattr_set_link	412
#define	FREEBSD64_SYS_freebsd64_extattr_get_link	413
#define	FREEBSD64_SYS_freebsd64_extattr_delete_link	414
#define	FREEBSD64_SYS_freebsd64___mac_execve	415
#define	FREEBSD64_SYS_freebsd64_sigaction	416
#define	FREEBSD64_SYS_freebsd64_sigreturn	417
#define	FREEBSD64_SYS_freebsd64_getcontext	421
#define	FREEBSD64_SYS_freebsd64_setcontext	422
#define	FREEBSD64_SYS_freebsd64_swapcontext	423
#define	FREEBSD64_SYS_freebsd64_swapoff	424
#define	FREEBSD64_SYS_freebsd64___acl_get_link	425
#define	FREEBSD64_SYS_freebsd64___acl_set_link	426
#define	FREEBSD64_SYS_freebsd64___acl_delete_link	427
#define	FREEBSD64_SYS_freebsd64___acl_aclcheck_link	428
#define	FREEBSD64_SYS_freebsd64_sigwait	429
#define	FREEBSD64_SYS_freebsd64_thr_create	430
#define	FREEBSD64_SYS_freebsd64_thr_exit	431
#define	FREEBSD64_SYS_freebsd64_thr_self	432
#define	FREEBSD64_SYS_thr_kill	433
#define	FREEBSD64_SYS_jail_attach	436
#define	FREEBSD64_SYS_freebsd64_extattr_list_fd	437
#define	FREEBSD64_SYS_freebsd64_extattr_list_file	438
#define	FREEBSD64_SYS_freebsd64_extattr_list_link	439
				/* 440 is obsolete kse_switchin */
#define	FREEBSD64_SYS_freebsd64_ksem_timedwait	441
#define	FREEBSD64_SYS_freebsd64_thr_suspend	442
#define	FREEBSD64_SYS_thr_wake	443
#define	FREEBSD64_SYS_kldunloadf	444
#define	FREEBSD64_SYS_freebsd64_audit	445
#define	FREEBSD64_SYS_freebsd64_auditon	446
#define	FREEBSD64_SYS_freebsd64_getauid	447
#define	FREEBSD64_SYS_freebsd64_setauid	448
#define	FREEBSD64_SYS_freebsd64_getaudit	449
#define	FREEBSD64_SYS_freebsd64_setaudit	450
#define	FREEBSD64_SYS_freebsd64_getaudit_addr	451
#define	FREEBSD64_SYS_freebsd64_setaudit_addr	452
#define	FREEBSD64_SYS_freebsd64_auditctl	453
#define	FREEBSD64_SYS_freebsd64__umtx_op	454
#define	FREEBSD64_SYS_freebsd64_thr_new	455
#define	FREEBSD64_SYS_freebsd64_sigqueue	456
#define	FREEBSD64_SYS_freebsd64_kmq_open	457
#define	FREEBSD64_SYS_freebsd64_kmq_setattr	458
#define	FREEBSD64_SYS_freebsd64_kmq_timedreceive	459
#define	FREEBSD64_SYS_freebsd64_kmq_timedsend	460
#define	FREEBSD64_SYS_freebsd64_kmq_notify	461
#define	FREEBSD64_SYS_freebsd64_kmq_unlink	462
#define	FREEBSD64_SYS_freebsd64_abort2	463
#define	FREEBSD64_SYS_freebsd64_thr_set_name	464
#define	FREEBSD64_SYS_freebsd64_aio_fsync	465
#define	FREEBSD64_SYS_freebsd64_rtprio_thread	466
#define	FREEBSD64_SYS_sctp_peeloff	471
#define	FREEBSD64_SYS_freebsd64_sctp_generic_sendmsg	472
#define	FREEBSD64_SYS_freebsd64_sctp_generic_sendmsg_iov	473
#define	FREEBSD64_SYS_freebsd64_sctp_generic_recvmsg	474
#define	FREEBSD64_SYS_freebsd64_pread	475
#define	FREEBSD64_SYS_freebsd64_pwrite	476
#define	FREEBSD64_SYS_freebsd64_mmap	477
#define	FREEBSD64_SYS_lseek	478
#define	FREEBSD64_SYS_freebsd64_truncate	479
#define	FREEBSD64_SYS_ftruncate	480
#define	FREEBSD64_SYS_thr_kill2	481
#define	FREEBSD64_SYS_freebsd12_freebsd64_shm_open	482
#define	FREEBSD64_SYS_freebsd64_shm_unlink	483
#define	FREEBSD64_SYS_freebsd64_cpuset	484
#define	FREEBSD64_SYS_cpuset_setid	485
#define	FREEBSD64_SYS_freebsd64_cpuset_getid	486
#define	FREEBSD64_SYS_freebsd64_cpuset_getaffinity	487
#define	FREEBSD64_SYS_freebsd64_cpuset_setaffinity	488
#define	FREEBSD64_SYS_freebsd64_faccessat	489
#define	FREEBSD64_SYS_freebsd64_fchmodat	490
#define	FREEBSD64_SYS_freebsd64_fchownat	491
#define	FREEBSD64_SYS_freebsd64_fexecve	492
#define	FREEBSD64_SYS_freebsd11_freebsd64_fstatat	493
#define	FREEBSD64_SYS_freebsd64_futimesat	494
#define	FREEBSD64_SYS_freebsd64_linkat	495
#define	FREEBSD64_SYS_freebsd64_mkdirat	496
#define	FREEBSD64_SYS_freebsd64_mkfifoat	497
#define	FREEBSD64_SYS_freebsd11_freebsd64_mknodat	498
#define	FREEBSD64_SYS_freebsd64_openat	499
#define	FREEBSD64_SYS_freebsd64_readlinkat	500
#define	FREEBSD64_SYS_freebsd64_renameat	501
#define	FREEBSD64_SYS_freebsd64_symlinkat	502
#define	FREEBSD64_SYS_freebsd64_unlinkat	503
#define	FREEBSD64_SYS_posix_openpt	504
#define	FREEBSD64_SYS_freebsd64_gssd_syscall	505
#define	FREEBSD64_SYS_freebsd64_jail_get	506
#define	FREEBSD64_SYS_freebsd64_jail_set	507
#define	FREEBSD64_SYS_jail_remove	508
#define	FREEBSD64_SYS_freebsd12_closefrom	509
#define	FREEBSD64_SYS_freebsd64___semctl	510
#define	FREEBSD64_SYS_freebsd64_msgctl	511
#define	FREEBSD64_SYS_freebsd64_shmctl	512
#define	FREEBSD64_SYS_freebsd64_lpathconf	513
				/* 514 is obsolete cap_new */
#define	FREEBSD64_SYS_freebsd64___cap_rights_get	515
#define	FREEBSD64_SYS_cap_enter	516
#define	FREEBSD64_SYS_freebsd64_cap_getmode	517
#define	FREEBSD64_SYS_freebsd64_pdfork	518
#define	FREEBSD64_SYS_pdkill	519
#define	FREEBSD64_SYS_freebsd64_pdgetpid	520
#define	FREEBSD64_SYS_freebsd64_pselect	522
#define	FREEBSD64_SYS_freebsd64_getloginclass	523
#define	FREEBSD64_SYS_freebsd64_setloginclass	524
#define	FREEBSD64_SYS_freebsd64_rctl_get_racct	525
#define	FREEBSD64_SYS_freebsd64_rctl_get_rules	526
#define	FREEBSD64_SYS_freebsd64_rctl_get_limits	527
#define	FREEBSD64_SYS_freebsd64_rctl_add_rule	528
#define	FREEBSD64_SYS_freebsd64_rctl_remove_rule	529
#define	FREEBSD64_SYS_posix_fallocate	530
#define	FREEBSD64_SYS_posix_fadvise	531
#define	FREEBSD64_SYS_freebsd64_wait6	532
#define	FREEBSD64_SYS_freebsd64_cap_rights_limit	533
#define	FREEBSD64_SYS_freebsd64_cap_ioctls_limit	534
#define	FREEBSD64_SYS_freebsd64_cap_ioctls_get	535
#define	FREEBSD64_SYS_cap_fcntls_limit	536
#define	FREEBSD64_SYS_freebsd64_cap_fcntls_get	537
#define	FREEBSD64_SYS_freebsd64_bindat	538
#define	FREEBSD64_SYS_freebsd64_connectat	539
#define	FREEBSD64_SYS_freebsd64_chflagsat	540
#define	FREEBSD64_SYS_freebsd64_accept4	541
#define	FREEBSD64_SYS_freebsd64_pipe2	542
#define	FREEBSD64_SYS_freebsd64_aio_mlock	543
#define	FREEBSD64_SYS_freebsd64_procctl	544
#define	FREEBSD64_SYS_freebsd64_ppoll	545
#define	FREEBSD64_SYS_freebsd64_futimens	546
#define	FREEBSD64_SYS_freebsd64_utimensat	547
				/* 548 is obsolete numa_getaffinity */
				/* 549 is obsolete numa_setaffinity */
#define	FREEBSD64_SYS_fdatasync	550
#define	FREEBSD64_SYS_freebsd64_fstat	551
#define	FREEBSD64_SYS_freebsd64_fstatat	552
#define	FREEBSD64_SYS_freebsd64_fhstat	553
#define	FREEBSD64_SYS_freebsd64_getdirentries	554
#define	FREEBSD64_SYS_freebsd64_statfs	555
#define	FREEBSD64_SYS_freebsd64_fstatfs	556
#define	FREEBSD64_SYS_freebsd64_getfsstat	557
#define	FREEBSD64_SYS_freebsd64_fhstatfs	558
#define	FREEBSD64_SYS_freebsd64_mknodat	559
#define	FREEBSD64_SYS_freebsd64_kevent	560
#define	FREEBSD64_SYS_freebsd64_cpuset_getdomain	561
#define	FREEBSD64_SYS_freebsd64_cpuset_setdomain	562
#define	FREEBSD64_SYS_freebsd64_getrandom	563
#define	FREEBSD64_SYS_freebsd64_getfhat	564
#define	FREEBSD64_SYS_freebsd64_fhlink	565
#define	FREEBSD64_SYS_freebsd64_fhlinkat	566
#define	FREEBSD64_SYS_freebsd64_fhreadlink	567
#define	FREEBSD64_SYS_freebsd64_funlinkat	568
#define	FREEBSD64_SYS_freebsd64_copy_file_range	569
#define	FREEBSD64_SYS_freebsd64___sysctlbyname	570
#define	FREEBSD64_SYS_freebsd64_shm_open2	571
#define	FREEBSD64_SYS_freebsd64_shm_rename	572
#define	FREEBSD64_SYS_freebsd64_sigfastblock	573
#define	FREEBSD64_SYS_freebsd64___realpathat	574
#define	FREEBSD64_SYS_close_range	575
#define	FREEBSD64_SYS_freebsd64_rpctls_syscall	576
#define	FREEBSD64_SYS_MAXSYSCALL	577
