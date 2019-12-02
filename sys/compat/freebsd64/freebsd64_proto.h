/*
 * System call prototypes.
 *
 * DO NOT EDIT-- this file is automatically @generated.
 * $FreeBSD$
 */

#ifndef _FREEBSD64_PROTO_H_
#define	_FREEBSD64_PROTO_H_

#include <sys/signal.h>
#include <sys/acl.h>
#include <sys/cpuset.h>
#include <sys/domainset.h>
#include <sys/_ffcounter.h>
#include <sys/_semaphore.h>
#include <sys/ucontext.h>
#include <sys/wait.h>

#include <bsm/audit_kevents.h>

struct proc;

struct thread;

#define	PAD_(t)	(sizeof(syscallarg_t) <= sizeof(t) ? \
		0 : sizeof(syscallarg_t) - sizeof(t))

#if BYTE_ORDER == LITTLE_ENDIAN
#define	PADL_(t)	0
#define	PADR_(t)	PAD_(t)
#elif defined(_MIPS_SZCAP) && _MIPS_SZCAP == 256
/*
 * For non-capability arguments, the syscall argument is stored in the
 * cursor field in the second word.
 */
#define	PADL_(t)	(sizeof (t) > sizeof(register_t) ? \
		0 : 2 * sizeof(register_t) - sizeof(t))
#define	PADR_(t)	(sizeof (t) > sizeof(register_t) ? \
		0 : 2 * sizeof(register_t))
#else
#define	PADL_(t)	PAD_(t)
#define	PADR_(t)	0
#endif

struct freebsd64_read_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(void *)]; void * buf; char buf_r_[PADR_(void *)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
};
struct freebsd64_write_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(const void *)]; const void * buf; char buf_r_[PADR_(const void *)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
};
struct freebsd64_open_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct freebsd64_wait4_args {
	char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
	char status_l_[PADL_(int *)]; int * status; char status_r_[PADR_(int *)];
	char options_l_[PADL_(int)]; int options; char options_r_[PADR_(int)];
	char rusage_l_[PADL_(struct rusage *)]; struct rusage * rusage; char rusage_r_[PADR_(struct rusage *)];
};
struct freebsd64_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char to_l_[PADL_(const char *)]; const char * to; char to_r_[PADR_(const char *)];
};
struct freebsd64_unlink_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_chdir_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_chmod_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct freebsd64_chown_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char uid_l_[PADL_(int)]; int uid; char uid_r_[PADR_(int)];
	char gid_l_[PADL_(int)]; int gid; char gid_r_[PADR_(int)];
};
struct freebsd64_break_args {
	char nsize_l_[PADL_(char *)]; char * nsize; char nsize_r_[PADR_(char *)];
};
struct freebsd64_mount_args {
	char type_l_[PADL_(const char *)]; const char * type; char type_r_[PADR_(const char *)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
};
struct freebsd64_unmount_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_ptrace_args {
	char req_l_[PADL_(int)]; int req; char req_r_[PADR_(int)];
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char addr_l_[PADL_(char *)]; char * addr; char addr_r_[PADR_(char *)];
	char data_l_[PADL_(int)]; int data; char data_r_[PADR_(int)];
};
struct freebsd64_recvmsg_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char msg_l_[PADL_(struct msghdr64 *)]; struct msghdr64 * msg; char msg_r_[PADR_(struct msghdr64 *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_sendmsg_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char msg_l_[PADL_(const struct msghdr64 *)]; const struct msghdr64 * msg; char msg_r_[PADR_(const struct msghdr64 *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_recvfrom_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char buf_l_[PADL_(void *)]; void * buf; char buf_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char from_l_[PADL_(struct sockaddr *)]; struct sockaddr * from; char from_r_[PADR_(struct sockaddr *)];
	char fromlenaddr_l_[PADL_(__socklen_t *)]; __socklen_t * fromlenaddr; char fromlenaddr_r_[PADR_(__socklen_t *)];
};
struct freebsd64_accept_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(struct sockaddr *)]; struct sockaddr * name; char name_r_[PADR_(struct sockaddr *)];
	char anamelen_l_[PADL_(__socklen_t *)]; __socklen_t * anamelen; char anamelen_r_[PADR_(__socklen_t *)];
};
struct freebsd64_getpeername_args {
	char fdes_l_[PADL_(int)]; int fdes; char fdes_r_[PADR_(int)];
	char asa_l_[PADL_(struct sockaddr *)]; struct sockaddr * asa; char asa_r_[PADR_(struct sockaddr *)];
	char alen_l_[PADL_(__socklen_t *)]; __socklen_t * alen; char alen_r_[PADR_(__socklen_t *)];
};
struct freebsd64_getsockname_args {
	char fdes_l_[PADL_(int)]; int fdes; char fdes_r_[PADR_(int)];
	char asa_l_[PADL_(struct sockaddr *)]; struct sockaddr * asa; char asa_r_[PADR_(struct sockaddr *)];
	char alen_l_[PADL_(__socklen_t *)]; __socklen_t * alen; char alen_r_[PADR_(__socklen_t *)];
};
struct freebsd64_access_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char amode_l_[PADL_(int)]; int amode; char amode_r_[PADR_(int)];
};
struct freebsd64_chflags_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(u_long)]; u_long flags; char flags_r_[PADR_(u_long)];
};
struct freebsd64_profil_args {
	char samples_l_[PADL_(char *)]; char * samples; char samples_r_[PADR_(char *)];
	char size_l_[PADL_(size_t)]; size_t size; char size_r_[PADR_(size_t)];
	char offset_l_[PADL_(size_t)]; size_t offset; char offset_r_[PADR_(size_t)];
	char scale_l_[PADL_(u_int)]; u_int scale; char scale_r_[PADR_(u_int)];
};
struct freebsd64_ktrace_args {
	char fname_l_[PADL_(const char *)]; const char * fname; char fname_r_[PADR_(const char *)];
	char ops_l_[PADL_(int)]; int ops; char ops_r_[PADR_(int)];
	char facs_l_[PADL_(int)]; int facs; char facs_r_[PADR_(int)];
	char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
};
struct freebsd64_getlogin_args {
	char namebuf_l_[PADL_(char *)]; char * namebuf; char namebuf_r_[PADR_(char *)];
	char namelen_l_[PADL_(u_int)]; u_int namelen; char namelen_r_[PADR_(u_int)];
};
struct freebsd64_setlogin_args {
	char namebuf_l_[PADL_(const char *)]; const char * namebuf; char namebuf_r_[PADR_(const char *)];
};
struct freebsd64_acct_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_sigaltstack_args {
	char ss_l_[PADL_(const struct sigaltstack64 *)]; const struct sigaltstack64 * ss; char ss_r_[PADR_(const struct sigaltstack64 *)];
	char oss_l_[PADL_(struct sigaltstack64 *)]; struct sigaltstack64 * oss; char oss_r_[PADR_(struct sigaltstack64 *)];
};
struct freebsd64_ioctl_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char com_l_[PADL_(u_long)]; u_long com; char com_r_[PADR_(u_long)];
	char data_l_[PADL_(char *)]; char * data; char data_r_[PADR_(char *)];
};
struct freebsd64_revoke_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_symlink_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char link_l_[PADL_(const char *)]; const char * link; char link_r_[PADR_(const char *)];
};
struct freebsd64_readlink_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char count_l_[PADL_(size_t)]; size_t count; char count_r_[PADR_(size_t)];
};
struct freebsd64_execve_args {
	char fname_l_[PADL_(const char *)]; const char * fname; char fname_r_[PADR_(const char *)];
	char argv_l_[PADL_(char **)]; char ** argv; char argv_r_[PADR_(char **)];
	char envv_l_[PADL_(char **)]; char ** envv; char envv_r_[PADR_(char **)];
};
struct freebsd64_chroot_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_msync_args {
	char addr_l_[PADL_(void *)]; void * addr; char addr_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_munmap_args {
	char addr_l_[PADL_(void *)]; void * addr; char addr_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
};
struct freebsd64_mprotect_args {
	char addr_l_[PADL_(const void *)]; const void * addr; char addr_r_[PADR_(const void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char prot_l_[PADL_(int)]; int prot; char prot_r_[PADR_(int)];
};
struct freebsd64_madvise_args {
	char addr_l_[PADL_(void *)]; void * addr; char addr_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char behav_l_[PADL_(int)]; int behav; char behav_r_[PADR_(int)];
};
struct freebsd64_mincore_args {
	char addr_l_[PADL_(const void *)]; const void * addr; char addr_r_[PADR_(const void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char vec_l_[PADL_(char *)]; char * vec; char vec_r_[PADR_(char *)];
};
struct freebsd64_getgroups_args {
	char gidsetsize_l_[PADL_(u_int)]; u_int gidsetsize; char gidsetsize_r_[PADR_(u_int)];
	char gidset_l_[PADL_(gid_t *)]; gid_t * gidset; char gidset_r_[PADR_(gid_t *)];
};
struct freebsd64_setgroups_args {
	char gidsetsize_l_[PADL_(u_int)]; u_int gidsetsize; char gidsetsize_r_[PADR_(u_int)];
	char gidset_l_[PADL_(const gid_t *)]; const gid_t * gidset; char gidset_r_[PADR_(const gid_t *)];
};
struct freebsd64_setitimer_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char itv_l_[PADL_(const struct itimerval *)]; const struct itimerval * itv; char itv_r_[PADR_(const struct itimerval *)];
	char oitv_l_[PADL_(struct itimerval *)]; struct itimerval * oitv; char oitv_r_[PADR_(struct itimerval *)];
};
struct freebsd64_swapon_args {
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
};
struct freebsd64_getitimer_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char itv_l_[PADL_(struct itimerval *)]; struct itimerval * itv; char itv_r_[PADR_(struct itimerval *)];
};
struct freebsd64_fcntl_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char arg_l_[PADL_(intptr_t)]; intptr_t arg; char arg_r_[PADR_(intptr_t)];
};
struct freebsd64_select_args {
	char nd_l_[PADL_(int)]; int nd; char nd_r_[PADR_(int)];
	char in_l_[PADL_(fd_set *)]; fd_set * in; char in_r_[PADR_(fd_set *)];
	char ou_l_[PADL_(fd_set *)]; fd_set * ou; char ou_r_[PADR_(fd_set *)];
	char ex_l_[PADL_(fd_set *)]; fd_set * ex; char ex_r_[PADR_(fd_set *)];
	char tv_l_[PADL_(struct timeval *)]; struct timeval * tv; char tv_r_[PADR_(struct timeval *)];
};
struct freebsd64_connect_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(const struct sockaddr *)]; const struct sockaddr * name; char name_r_[PADR_(const struct sockaddr *)];
	char namelen_l_[PADL_(__socklen_t)]; __socklen_t namelen; char namelen_r_[PADR_(__socklen_t)];
};
struct freebsd64_bind_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(const struct sockaddr *)]; const struct sockaddr * name; char name_r_[PADR_(const struct sockaddr *)];
	char namelen_l_[PADL_(__socklen_t)]; __socklen_t namelen; char namelen_r_[PADR_(__socklen_t)];
};
struct freebsd64_setsockopt_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char level_l_[PADL_(int)]; int level; char level_r_[PADR_(int)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
	char val_l_[PADL_(const void *)]; const void * val; char val_r_[PADR_(const void *)];
	char valsize_l_[PADL_(__socklen_t)]; __socklen_t valsize; char valsize_r_[PADR_(__socklen_t)];
};
struct freebsd64_gettimeofday_args {
	char tp_l_[PADL_(struct timeval *)]; struct timeval * tp; char tp_r_[PADR_(struct timeval *)];
	char tzp_l_[PADL_(struct timezone *)]; struct timezone * tzp; char tzp_r_[PADR_(struct timezone *)];
};
struct freebsd64_getrusage_args {
	char who_l_[PADL_(int)]; int who; char who_r_[PADR_(int)];
	char rusage_l_[PADL_(struct rusage *)]; struct rusage * rusage; char rusage_r_[PADR_(struct rusage *)];
};
struct freebsd64_getsockopt_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char level_l_[PADL_(int)]; int level; char level_r_[PADR_(int)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
	char val_l_[PADL_(void *)]; void * val; char val_r_[PADR_(void *)];
	char avalsize_l_[PADL_(__socklen_t *)]; __socklen_t * avalsize; char avalsize_r_[PADR_(__socklen_t *)];
};
struct freebsd64_readv_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec64 *)]; struct iovec64 * iovp; char iovp_r_[PADR_(struct iovec64 *)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
};
struct freebsd64_writev_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec64 *)]; struct iovec64 * iovp; char iovp_r_[PADR_(struct iovec64 *)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
};
struct freebsd64_settimeofday_args {
	char tv_l_[PADL_(const struct timeval *)]; const struct timeval * tv; char tv_r_[PADR_(const struct timeval *)];
	char tzp_l_[PADL_(const struct timezone *)]; const struct timezone * tzp; char tzp_r_[PADR_(const struct timezone *)];
};
struct freebsd64_rename_args {
	char from_l_[PADL_(const char *)]; const char * from; char from_r_[PADR_(const char *)];
	char to_l_[PADL_(const char *)]; const char * to; char to_r_[PADR_(const char *)];
};
struct freebsd64_mkfifo_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct freebsd64_sendto_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char buf_l_[PADL_(const void *)]; const void * buf; char buf_r_[PADR_(const void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char to_l_[PADL_(const struct sockaddr *)]; const struct sockaddr * to; char to_r_[PADR_(const struct sockaddr *)];
	char tolen_l_[PADL_(__socklen_t)]; __socklen_t tolen; char tolen_r_[PADR_(__socklen_t)];
};
struct freebsd64_socketpair_args {
	char domain_l_[PADL_(int)]; int domain; char domain_r_[PADR_(int)];
	char type_l_[PADL_(int)]; int type; char type_r_[PADR_(int)];
	char protocol_l_[PADL_(int)]; int protocol; char protocol_r_[PADR_(int)];
	char rsv_l_[PADL_(int *)]; int * rsv; char rsv_r_[PADR_(int *)];
};
struct freebsd64_mkdir_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct freebsd64_rmdir_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_utimes_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char tptr_l_[PADL_(const struct timeval *)]; const struct timeval * tptr; char tptr_r_[PADR_(const struct timeval *)];
};
struct freebsd64_adjtime_args {
	char delta_l_[PADL_(const struct timeval *)]; const struct timeval * delta; char delta_r_[PADR_(const struct timeval *)];
	char olddelta_l_[PADL_(struct timeval *)]; struct timeval * olddelta; char olddelta_r_[PADR_(struct timeval *)];
};
struct freebsd64_quotactl_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char uid_l_[PADL_(int)]; int uid; char uid_r_[PADR_(int)];
	char arg_l_[PADL_(void *)]; void * arg; char arg_r_[PADR_(void *)];
};
struct freebsd64_nlm_syscall_args {
	char debug_level_l_[PADL_(int)]; int debug_level; char debug_level_r_[PADR_(int)];
	char grace_period_l_[PADL_(int)]; int grace_period; char grace_period_r_[PADR_(int)];
	char addr_count_l_[PADL_(int)]; int addr_count; char addr_count_r_[PADR_(int)];
	char addrs_l_[PADL_(char **)]; char ** addrs; char addrs_r_[PADR_(char **)];
};
struct freebsd64_nfssvc_args {
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
	char argp_l_[PADL_(void *)]; void * argp; char argp_r_[PADR_(void *)];
};
struct freebsd64_lgetfh_args {
	char fname_l_[PADL_(const char *)]; const char * fname; char fname_r_[PADR_(const char *)];
	char fhp_l_[PADL_(struct fhandle *)]; struct fhandle * fhp; char fhp_r_[PADR_(struct fhandle *)];
};
struct freebsd64_getfh_args {
	char fname_l_[PADL_(const char *)]; const char * fname; char fname_r_[PADR_(const char *)];
	char fhp_l_[PADL_(struct fhandle *)]; struct fhandle * fhp; char fhp_r_[PADR_(struct fhandle *)];
};
struct freebsd64_sysarch_args {
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char parms_l_[PADL_(char *)]; char * parms; char parms_r_[PADR_(char *)];
};
struct freebsd64_rtprio_args {
	char function_l_[PADL_(int)]; int function; char function_r_[PADR_(int)];
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char rtp_l_[PADL_(struct rtprio *)]; struct rtprio * rtp; char rtp_r_[PADR_(struct rtprio *)];
};
struct freebsd64_semsys_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char a2_l_[PADL_(intptr_t)]; intptr_t a2; char a2_r_[PADR_(intptr_t)];
	char a3_l_[PADL_(intptr_t)]; intptr_t a3; char a3_r_[PADR_(intptr_t)];
	char a4_l_[PADL_(intptr_t)]; intptr_t a4; char a4_r_[PADR_(intptr_t)];
	char a5_l_[PADL_(intptr_t)]; intptr_t a5; char a5_r_[PADR_(intptr_t)];
};
struct freebsd64_msgsys_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char a2_l_[PADL_(intptr_t)]; intptr_t a2; char a2_r_[PADR_(intptr_t)];
	char a3_l_[PADL_(intptr_t)]; intptr_t a3; char a3_r_[PADR_(intptr_t)];
	char a4_l_[PADL_(intptr_t)]; intptr_t a4; char a4_r_[PADR_(intptr_t)];
	char a5_l_[PADL_(intptr_t)]; intptr_t a5; char a5_r_[PADR_(intptr_t)];
	char a6_l_[PADL_(intptr_t)]; intptr_t a6; char a6_r_[PADR_(intptr_t)];
};
struct freebsd64_shmsys_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char a2_l_[PADL_(intptr_t)]; intptr_t a2; char a2_r_[PADR_(intptr_t)];
	char a3_l_[PADL_(intptr_t)]; intptr_t a3; char a3_r_[PADR_(intptr_t)];
	char a4_l_[PADL_(intptr_t)]; intptr_t a4; char a4_r_[PADR_(intptr_t)];
};
struct freebsd64_ntp_adjtime_args {
	char tp_l_[PADL_(struct timex *)]; struct timex * tp; char tp_r_[PADR_(struct timex *)];
};
struct freebsd64_pathconf_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
};
struct freebsd64___getrlimit_args {
	char which_l_[PADL_(u_int)]; u_int which; char which_r_[PADR_(u_int)];
	char rlp_l_[PADL_(struct rlimit *)]; struct rlimit * rlp; char rlp_r_[PADR_(struct rlimit *)];
};
struct freebsd64___setrlimit_args {
	char which_l_[PADL_(u_int)]; u_int which; char which_r_[PADR_(u_int)];
	char rlp_l_[PADL_(struct rlimit *)]; struct rlimit * rlp; char rlp_r_[PADR_(struct rlimit *)];
};
struct freebsd64___sysctl_args {
	char name_l_[PADL_(int *)]; int * name; char name_r_[PADR_(int *)];
	char namelen_l_[PADL_(u_int)]; u_int namelen; char namelen_r_[PADR_(u_int)];
	char old_l_[PADL_(void *)]; void * old; char old_r_[PADR_(void *)];
	char oldlenp_l_[PADL_(size_t *)]; size_t * oldlenp; char oldlenp_r_[PADR_(size_t *)];
	char new_l_[PADL_(const void *)]; const void * new; char new_r_[PADR_(const void *)];
	char newlen_l_[PADL_(size_t)]; size_t newlen; char newlen_r_[PADR_(size_t)];
};
struct freebsd64_mlock_args {
	char addr_l_[PADL_(const void *)]; const void * addr; char addr_r_[PADR_(const void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
};
struct freebsd64_munlock_args {
	char addr_l_[PADL_(const void *)]; const void * addr; char addr_r_[PADR_(const void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
};
struct freebsd64_undelete_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_futimes_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char tptr_l_[PADL_(const struct timeval *)]; const struct timeval * tptr; char tptr_r_[PADR_(const struct timeval *)];
};
struct freebsd64_poll_args {
	char fds_l_[PADL_(struct pollfd *)]; struct pollfd * fds; char fds_r_[PADR_(struct pollfd *)];
	char nfds_l_[PADL_(u_int)]; u_int nfds; char nfds_r_[PADR_(u_int)];
	char timeout_l_[PADL_(int)]; int timeout; char timeout_r_[PADR_(int)];
};
struct freebsd64_semop_args {
	char semid_l_[PADL_(int)]; int semid; char semid_r_[PADR_(int)];
	char sops_l_[PADL_(struct sembuf *)]; struct sembuf * sops; char sops_r_[PADR_(struct sembuf *)];
	char nsops_l_[PADL_(size_t)]; size_t nsops; char nsops_r_[PADR_(size_t)];
};
struct freebsd64_msgsnd_args {
	char msqid_l_[PADL_(int)]; int msqid; char msqid_r_[PADR_(int)];
	char msgp_l_[PADL_(const void *)]; const void * msgp; char msgp_r_[PADR_(const void *)];
	char msgsz_l_[PADL_(size_t)]; size_t msgsz; char msgsz_r_[PADR_(size_t)];
	char msgflg_l_[PADL_(int)]; int msgflg; char msgflg_r_[PADR_(int)];
};
struct freebsd64_msgrcv_args {
	char msqid_l_[PADL_(int)]; int msqid; char msqid_r_[PADR_(int)];
	char msgp_l_[PADL_(void *)]; void * msgp; char msgp_r_[PADR_(void *)];
	char msgsz_l_[PADL_(size_t)]; size_t msgsz; char msgsz_r_[PADR_(size_t)];
	char msgtyp_l_[PADL_(long)]; long msgtyp; char msgtyp_r_[PADR_(long)];
	char msgflg_l_[PADL_(int)]; int msgflg; char msgflg_r_[PADR_(int)];
};
struct freebsd64_shmat_args {
	char shmid_l_[PADL_(int)]; int shmid; char shmid_r_[PADR_(int)];
	char shmaddr_l_[PADL_(const void *)]; const void * shmaddr; char shmaddr_r_[PADR_(const void *)];
	char shmflg_l_[PADL_(int)]; int shmflg; char shmflg_r_[PADR_(int)];
};
struct freebsd64_shmdt_args {
	char shmaddr_l_[PADL_(const void *)]; const void * shmaddr; char shmaddr_r_[PADR_(const void *)];
};
struct freebsd64_clock_gettime_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char tp_l_[PADL_(struct timespec *)]; struct timespec * tp; char tp_r_[PADR_(struct timespec *)];
};
struct freebsd64_clock_settime_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char tp_l_[PADL_(const struct timespec *)]; const struct timespec * tp; char tp_r_[PADR_(const struct timespec *)];
};
struct freebsd64_clock_getres_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char tp_l_[PADL_(struct timespec *)]; struct timespec * tp; char tp_r_[PADR_(struct timespec *)];
};
struct freebsd64_ktimer_create_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char evp_l_[PADL_(struct sigevent64 *)]; struct sigevent64 * evp; char evp_r_[PADR_(struct sigevent64 *)];
	char timerid_l_[PADL_(int *)]; int * timerid; char timerid_r_[PADR_(int *)];
};
struct freebsd64_ktimer_settime_args {
	char timerid_l_[PADL_(int)]; int timerid; char timerid_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char value_l_[PADL_(const struct itimerspec *)]; const struct itimerspec * value; char value_r_[PADR_(const struct itimerspec *)];
	char ovalue_l_[PADL_(struct itimerspec *)]; struct itimerspec * ovalue; char ovalue_r_[PADR_(struct itimerspec *)];
};
struct freebsd64_ktimer_gettime_args {
	char timerid_l_[PADL_(int)]; int timerid; char timerid_r_[PADR_(int)];
	char value_l_[PADL_(struct itimerspec *)]; struct itimerspec * value; char value_r_[PADR_(struct itimerspec *)];
};
struct freebsd64_nanosleep_args {
	char rqtp_l_[PADL_(const struct timespec *)]; const struct timespec * rqtp; char rqtp_r_[PADR_(const struct timespec *)];
	char rmtp_l_[PADL_(struct timespec *)]; struct timespec * rmtp; char rmtp_r_[PADR_(struct timespec *)];
};
struct freebsd64_ffclock_getcounter_args {
	char ffcount_l_[PADL_(ffcounter *)]; ffcounter * ffcount; char ffcount_r_[PADR_(ffcounter *)];
};
struct freebsd64_ffclock_setestimate_args {
	char cest_l_[PADL_(struct ffclock_estimate *)]; struct ffclock_estimate * cest; char cest_r_[PADR_(struct ffclock_estimate *)];
};
struct freebsd64_ffclock_getestimate_args {
	char cest_l_[PADL_(struct ffclock_estimate *)]; struct ffclock_estimate * cest; char cest_r_[PADR_(struct ffclock_estimate *)];
};
struct freebsd64_clock_nanosleep_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char rqtp_l_[PADL_(const struct timespec *)]; const struct timespec * rqtp; char rqtp_r_[PADR_(const struct timespec *)];
	char rmtp_l_[PADL_(struct timespec *)]; struct timespec * rmtp; char rmtp_r_[PADR_(struct timespec *)];
};
struct freebsd64_clock_getcpuclockid2_args {
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char clock_id_l_[PADL_(clockid_t *)]; clockid_t * clock_id; char clock_id_r_[PADR_(clockid_t *)];
};
struct freebsd64_ntp_gettime_args {
	char ntvp_l_[PADL_(struct ntptimeval *)]; struct ntptimeval * ntvp; char ntvp_r_[PADR_(struct ntptimeval *)];
};
struct freebsd64_minherit_args {
	char addr_l_[PADL_(void *)]; void * addr; char addr_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char inherit_l_[PADL_(int)]; int inherit; char inherit_r_[PADR_(int)];
};
struct freebsd64_lchown_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char uid_l_[PADL_(int)]; int uid; char uid_r_[PADR_(int)];
	char gid_l_[PADL_(int)]; int gid; char gid_r_[PADR_(int)];
};
struct freebsd64_aio_read_args {
	char aiocbp_l_[PADL_(struct aiocb64 *)]; struct aiocb64 * aiocbp; char aiocbp_r_[PADR_(struct aiocb64 *)];
};
struct freebsd64_aio_write_args {
	char aiocbp_l_[PADL_(struct aiocb64 *)]; struct aiocb64 * aiocbp; char aiocbp_r_[PADR_(struct aiocb64 *)];
};
struct freebsd64_lio_listio_args {
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
	char acb_list_l_[PADL_(struct aiocb64 *const *)]; struct aiocb64 *const * acb_list; char acb_list_r_[PADR_(struct aiocb64 *const *)];
	char nent_l_[PADL_(int)]; int nent; char nent_r_[PADR_(int)];
	char sig_l_[PADL_(struct sigevent64 *)]; struct sigevent64 * sig; char sig_r_[PADR_(struct sigevent64 *)];
};
struct freebsd64_kbounce_args {
	char src_l_[PADL_(const void *)]; const void * src; char src_r_[PADR_(const void *)];
	char dst_l_[PADL_(void *)]; void * dst; char dst_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_lchmod_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct freebsd64_lutimes_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char tptr_l_[PADL_(const struct timeval *)]; const struct timeval * tptr; char tptr_r_[PADR_(const struct timeval *)];
};
struct freebsd64_preadv_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec64 *)]; struct iovec64 * iovp; char iovp_r_[PADR_(struct iovec64 *)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct freebsd64_pwritev_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec64 *)]; struct iovec64 * iovp; char iovp_r_[PADR_(struct iovec64 *)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct freebsd64_fhopen_args {
	char u_fhp_l_[PADL_(const struct fhandle *)]; const struct fhandle * u_fhp; char u_fhp_r_[PADR_(const struct fhandle *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_modstat_args {
	char modid_l_[PADL_(int)]; int modid; char modid_r_[PADR_(int)];
	char stat_l_[PADL_(struct module_stat *)]; struct module_stat * stat; char stat_r_[PADR_(struct module_stat *)];
};
struct freebsd64_modfind_args {
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
};
struct freebsd64_kldload_args {
	char file_l_[PADL_(const char *)]; const char * file; char file_r_[PADR_(const char *)];
};
struct freebsd64_kldfind_args {
	char file_l_[PADL_(const char *)]; const char * file; char file_r_[PADR_(const char *)];
};
struct freebsd64_kldstat_args {
	char fileid_l_[PADL_(int)]; int fileid; char fileid_r_[PADR_(int)];
	char stat_l_[PADL_(struct kld_file_stat64 *)]; struct kld_file_stat64 * stat; char stat_r_[PADR_(struct kld_file_stat64 *)];
};
struct freebsd64_aio_return_args {
	char aiocbp_l_[PADL_(struct aiocb64 *)]; struct aiocb64 * aiocbp; char aiocbp_r_[PADR_(struct aiocb64 *)];
};
struct freebsd64_aio_suspend_args {
	char aiocbp_l_[PADL_(struct aiocb64 *const *)]; struct aiocb64 *const * aiocbp; char aiocbp_r_[PADR_(struct aiocb64 *const *)];
	char nent_l_[PADL_(int)]; int nent; char nent_r_[PADR_(int)];
	char timeout_l_[PADL_(const struct timespec *)]; const struct timespec * timeout; char timeout_r_[PADR_(const struct timespec *)];
};
struct freebsd64_aio_cancel_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char aiocbp_l_[PADL_(struct aiocb64 *)]; struct aiocb64 * aiocbp; char aiocbp_r_[PADR_(struct aiocb64 *)];
};
struct freebsd64_aio_error_args {
	char aiocbp_l_[PADL_(struct aiocb64 *)]; struct aiocb64 * aiocbp; char aiocbp_r_[PADR_(struct aiocb64 *)];
};
struct freebsd64___getcwd_args {
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char buflen_l_[PADL_(size_t)]; size_t buflen; char buflen_r_[PADR_(size_t)];
};
struct freebsd64_sched_setparam_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char param_l_[PADL_(const struct sched_param *)]; const struct sched_param * param; char param_r_[PADR_(const struct sched_param *)];
};
struct freebsd64_sched_getparam_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char param_l_[PADL_(struct sched_param *)]; struct sched_param * param; char param_r_[PADR_(struct sched_param *)];
};
struct freebsd64_sched_setscheduler_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char policy_l_[PADL_(int)]; int policy; char policy_r_[PADR_(int)];
	char param_l_[PADL_(const struct sched_param *)]; const struct sched_param * param; char param_r_[PADR_(const struct sched_param *)];
};
struct freebsd64_sched_rr_get_interval_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char interval_l_[PADL_(struct timespec *)]; struct timespec * interval; char interval_r_[PADR_(struct timespec *)];
};
struct freebsd64_utrace_args {
	char addr_l_[PADL_(const void *)]; const void * addr; char addr_r_[PADR_(const void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
};
struct freebsd64_kldsym_args {
	char fileid_l_[PADL_(int)]; int fileid; char fileid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
};
struct freebsd64_jail_args {
	char jailp_l_[PADL_(struct jail64 *)]; struct jail64 * jailp; char jailp_r_[PADR_(struct jail64 *)];
};
struct freebsd64_nnpfs_syscall_args {
	char operation_l_[PADL_(int)]; int operation; char operation_r_[PADR_(int)];
	char a_pathP_l_[PADL_(char *)]; char * a_pathP; char a_pathP_r_[PADR_(char *)];
	char a_opcode_l_[PADL_(int)]; int a_opcode; char a_opcode_r_[PADR_(int)];
	char a_paramsP_l_[PADL_(void *)]; void * a_paramsP; char a_paramsP_r_[PADR_(void *)];
	char a_followSymlinks_l_[PADL_(int)]; int a_followSymlinks; char a_followSymlinks_r_[PADR_(int)];
};
struct freebsd64_sigprocmask_args {
	char how_l_[PADL_(int)]; int how; char how_r_[PADR_(int)];
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
	char oset_l_[PADL_(sigset_t *)]; sigset_t * oset; char oset_r_[PADR_(sigset_t *)];
};
struct freebsd64_sigsuspend_args {
	char sigmask_l_[PADL_(const sigset_t *)]; const sigset_t * sigmask; char sigmask_r_[PADR_(const sigset_t *)];
};
struct freebsd64_sigpending_args {
	char set_l_[PADL_(sigset_t *)]; sigset_t * set; char set_r_[PADR_(sigset_t *)];
};
struct freebsd64_sigtimedwait_args {
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
	char info_l_[PADL_(struct siginfo64 *)]; struct siginfo64 * info; char info_r_[PADR_(struct siginfo64 *)];
	char timeout_l_[PADL_(const struct timespec *)]; const struct timespec * timeout; char timeout_r_[PADR_(const struct timespec *)];
};
struct freebsd64_sigwaitinfo_args {
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
	char info_l_[PADL_(struct siginfo64 *)]; struct siginfo64 * info; char info_r_[PADR_(struct siginfo64 *)];
};
struct freebsd64___acl_get_file_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64___acl_set_file_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64___acl_get_fd_args {
	char filedes_l_[PADL_(int)]; int filedes; char filedes_r_[PADR_(int)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64___acl_set_fd_args {
	char filedes_l_[PADL_(int)]; int filedes; char filedes_r_[PADR_(int)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64___acl_delete_file_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
};
struct freebsd64___acl_aclcheck_file_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64___acl_aclcheck_fd_args {
	char filedes_l_[PADL_(int)]; int filedes; char filedes_r_[PADR_(int)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64_extattrctl_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char filename_l_[PADL_(const char *)]; const char * filename; char filename_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
};
struct freebsd64_extattr_set_file_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_extattr_get_file_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_extattr_delete_file_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
};
struct freebsd64_aio_waitcomplete_args {
	char aiocbp_l_[PADL_(struct aiocb64 **)]; struct aiocb64 ** aiocbp; char aiocbp_r_[PADR_(struct aiocb64 **)];
	char timeout_l_[PADL_(struct timespec *)]; struct timespec * timeout; char timeout_r_[PADR_(struct timespec *)];
};
struct freebsd64_getresuid_args {
	char ruid_l_[PADL_(uid_t *)]; uid_t * ruid; char ruid_r_[PADR_(uid_t *)];
	char euid_l_[PADL_(uid_t *)]; uid_t * euid; char euid_r_[PADR_(uid_t *)];
	char suid_l_[PADL_(uid_t *)]; uid_t * suid; char suid_r_[PADR_(uid_t *)];
};
struct freebsd64_getresgid_args {
	char rgid_l_[PADL_(gid_t *)]; gid_t * rgid; char rgid_r_[PADR_(gid_t *)];
	char egid_l_[PADL_(gid_t *)]; gid_t * egid; char egid_r_[PADR_(gid_t *)];
	char sgid_l_[PADL_(gid_t *)]; gid_t * sgid; char sgid_r_[PADR_(gid_t *)];
};
struct freebsd64_extattr_set_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_extattr_get_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_extattr_delete_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
};
struct freebsd64_eaccess_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char amode_l_[PADL_(int)]; int amode; char amode_r_[PADR_(int)];
};
struct freebsd64_nmount_args {
	char iovp_l_[PADL_(struct iovec64 *)]; struct iovec64 * iovp; char iovp_r_[PADR_(struct iovec64 *)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64___mac_get_proc_args {
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64___mac_set_proc_args {
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64___mac_get_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64___mac_get_file_args {
	char path_p_l_[PADL_(const char *)]; const char * path_p; char path_p_r_[PADR_(const char *)];
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64___mac_set_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64___mac_set_file_args {
	char path_p_l_[PADL_(const char *)]; const char * path_p; char path_p_r_[PADR_(const char *)];
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64_kenv_args {
	char what_l_[PADL_(int)]; int what; char what_r_[PADR_(int)];
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
	char value_l_[PADL_(char *)]; char * value; char value_r_[PADR_(char *)];
	char len_l_[PADL_(int)]; int len; char len_r_[PADR_(int)];
};
struct freebsd64_lchflags_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(u_long)]; u_long flags; char flags_r_[PADR_(u_long)];
};
struct freebsd64_uuidgen_args {
	char store_l_[PADL_(struct uuid *)]; struct uuid * store; char store_r_[PADR_(struct uuid *)];
	char count_l_[PADL_(int)]; int count; char count_r_[PADR_(int)];
};
struct freebsd64_sendfile_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
	char hdtr_l_[PADL_(struct sf_hdtr64 *)]; struct sf_hdtr64 * hdtr; char hdtr_r_[PADR_(struct sf_hdtr64 *)];
	char sbytes_l_[PADL_(off_t *)]; off_t * sbytes; char sbytes_r_[PADR_(off_t *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_mac_syscall_args {
	char policy_l_[PADL_(const char *)]; const char * policy; char policy_r_[PADR_(const char *)];
	char call_l_[PADL_(int)]; int call; char call_r_[PADR_(int)];
	char arg_l_[PADL_(void *)]; void * arg; char arg_r_[PADR_(void *)];
};
struct freebsd64_ksem_init_args {
	char idp_l_[PADL_(semid_t *)]; semid_t * idp; char idp_r_[PADR_(semid_t *)];
	char value_l_[PADL_(unsigned int)]; unsigned int value; char value_r_[PADR_(unsigned int)];
};
struct freebsd64_ksem_open_args {
	char idp_l_[PADL_(semid_t *)]; semid_t * idp; char idp_r_[PADR_(semid_t *)];
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
	char oflag_l_[PADL_(int)]; int oflag; char oflag_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char value_l_[PADL_(unsigned int)]; unsigned int value; char value_r_[PADR_(unsigned int)];
};
struct freebsd64_ksem_unlink_args {
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
};
struct freebsd64_ksem_getvalue_args {
	char id_l_[PADL_(semid_t)]; semid_t id; char id_r_[PADR_(semid_t)];
	char val_l_[PADL_(int *)]; int * val; char val_r_[PADR_(int *)];
};
struct freebsd64___mac_get_pid_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64___mac_get_link_args {
	char path_p_l_[PADL_(const char *)]; const char * path_p; char path_p_r_[PADR_(const char *)];
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64___mac_set_link_args {
	char path_p_l_[PADL_(const char *)]; const char * path_p; char path_p_r_[PADR_(const char *)];
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64_extattr_set_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_extattr_get_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_extattr_delete_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char *)]; const char * attrname; char attrname_r_[PADR_(const char *)];
};
struct freebsd64___mac_execve_args {
	char fname_l_[PADL_(const char *)]; const char * fname; char fname_r_[PADR_(const char *)];
	char argv_l_[PADL_(char **)]; char ** argv; char argv_r_[PADR_(char **)];
	char envv_l_[PADL_(char **)]; char ** envv; char envv_r_[PADR_(char **)];
	char mac_p_l_[PADL_(struct mac64 *)]; struct mac64 * mac_p; char mac_p_r_[PADR_(struct mac64 *)];
};
struct freebsd64_sigaction_args {
	char sig_l_[PADL_(int)]; int sig; char sig_r_[PADR_(int)];
	char act_l_[PADL_(const struct sigaction64 *)]; const struct sigaction64 * act; char act_r_[PADR_(const struct sigaction64 *)];
	char oact_l_[PADL_(struct sigaction64 *)]; struct sigaction64 * oact; char oact_r_[PADR_(struct sigaction64 *)];
};
struct freebsd64_sigreturn_args {
	char sigcntxp_l_[PADL_(const struct __ucontext64 *)]; const struct __ucontext64 * sigcntxp; char sigcntxp_r_[PADR_(const struct __ucontext64 *)];
};
struct freebsd64_getcontext_args {
	char ucp_l_[PADL_(struct __ucontext64 *)]; struct __ucontext64 * ucp; char ucp_r_[PADR_(struct __ucontext64 *)];
};
struct freebsd64_setcontext_args {
	char ucp_l_[PADL_(const struct __ucontext64 *)]; const struct __ucontext64 * ucp; char ucp_r_[PADR_(const struct __ucontext64 *)];
};
struct freebsd64_swapcontext_args {
	char oucp_l_[PADL_(struct __ucontext64 *)]; struct __ucontext64 * oucp; char oucp_r_[PADR_(struct __ucontext64 *)];
	char ucp_l_[PADL_(const struct __ucontext64 *)]; const struct __ucontext64 * ucp; char ucp_r_[PADR_(const struct __ucontext64 *)];
};
struct freebsd64_swapoff_args {
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
};
struct freebsd64___acl_get_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64___acl_set_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64___acl_delete_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
};
struct freebsd64___acl_aclcheck_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl *)]; struct acl * aclp; char aclp_r_[PADR_(struct acl *)];
};
struct freebsd64_sigwait_args {
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
	char sig_l_[PADL_(int *)]; int * sig; char sig_r_[PADR_(int *)];
};
struct freebsd64_thr_create_args {
	char ctx_l_[PADL_(struct __ucontext64 *)]; struct __ucontext64 * ctx; char ctx_r_[PADR_(struct __ucontext64 *)];
	char id_l_[PADL_(long *)]; long * id; char id_r_[PADR_(long *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_thr_exit_args {
	char state_l_[PADL_(long *)]; long * state; char state_r_[PADR_(long *)];
};
struct freebsd64_thr_self_args {
	char id_l_[PADL_(long *)]; long * id; char id_r_[PADR_(long *)];
};
struct freebsd64_extattr_list_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_extattr_list_file_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_extattr_list_link_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct freebsd64_ksem_timedwait_args {
	char id_l_[PADL_(semid_t)]; semid_t id; char id_r_[PADR_(semid_t)];
	char abstime_l_[PADL_(const struct timespec *)]; const struct timespec * abstime; char abstime_r_[PADR_(const struct timespec *)];
};
struct freebsd64_thr_suspend_args {
	char timeout_l_[PADL_(const struct timespec *)]; const struct timespec * timeout; char timeout_r_[PADR_(const struct timespec *)];
};
struct freebsd64_audit_args {
	char record_l_[PADL_(const void *)]; const void * record; char record_r_[PADR_(const void *)];
	char length_l_[PADL_(u_int)]; u_int length; char length_r_[PADR_(u_int)];
};
struct freebsd64_auditon_args {
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
	char length_l_[PADL_(u_int)]; u_int length; char length_r_[PADR_(u_int)];
};
struct freebsd64_getauid_args {
	char auid_l_[PADL_(uid_t *)]; uid_t * auid; char auid_r_[PADR_(uid_t *)];
};
struct freebsd64_setauid_args {
	char auid_l_[PADL_(uid_t *)]; uid_t * auid; char auid_r_[PADR_(uid_t *)];
};
struct freebsd64_getaudit_args {
	char auditinfo_l_[PADL_(struct auditinfo *)]; struct auditinfo * auditinfo; char auditinfo_r_[PADR_(struct auditinfo *)];
};
struct freebsd64_setaudit_args {
	char auditinfo_l_[PADL_(struct auditinfo *)]; struct auditinfo * auditinfo; char auditinfo_r_[PADR_(struct auditinfo *)];
};
struct freebsd64_getaudit_addr_args {
	char auditinfo_addr_l_[PADL_(struct auditinfo_addr *)]; struct auditinfo_addr * auditinfo_addr; char auditinfo_addr_r_[PADR_(struct auditinfo_addr *)];
	char length_l_[PADL_(u_int)]; u_int length; char length_r_[PADR_(u_int)];
};
struct freebsd64_setaudit_addr_args {
	char auditinfo_addr_l_[PADL_(struct auditinfo_addr *)]; struct auditinfo_addr * auditinfo_addr; char auditinfo_addr_r_[PADR_(struct auditinfo_addr *)];
	char length_l_[PADL_(u_int)]; u_int length; char length_r_[PADR_(u_int)];
};
struct freebsd64_auditctl_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64__umtx_op_args {
	char obj_l_[PADL_(void *)]; void * obj; char obj_r_[PADR_(void *)];
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char val_l_[PADL_(u_long)]; u_long val; char val_r_[PADR_(u_long)];
	char uaddr1_l_[PADL_(void *)]; void * uaddr1; char uaddr1_r_[PADR_(void *)];
	char uaddr2_l_[PADL_(void *)]; void * uaddr2; char uaddr2_r_[PADR_(void *)];
};
struct freebsd64_thr_new_args {
	char param_l_[PADL_(struct thr_param64 *)]; struct thr_param64 * param; char param_r_[PADR_(struct thr_param64 *)];
	char param_size_l_[PADL_(int)]; int param_size; char param_size_r_[PADR_(int)];
};
struct freebsd64_sigqueue_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char signum_l_[PADL_(int)]; int signum; char signum_r_[PADR_(int)];
	char value_l_[PADL_(void *)]; void * value; char value_r_[PADR_(void *)];
};
struct freebsd64_kmq_open_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char attr_l_[PADL_(const struct mq_attr *)]; const struct mq_attr * attr; char attr_r_[PADR_(const struct mq_attr *)];
};
struct freebsd64_kmq_setattr_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char attr_l_[PADL_(const struct mq_attr *)]; const struct mq_attr * attr; char attr_r_[PADR_(const struct mq_attr *)];
	char oattr_l_[PADL_(struct mq_attr *)]; struct mq_attr * oattr; char oattr_r_[PADR_(struct mq_attr *)];
};
struct freebsd64_kmq_timedreceive_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char msg_ptr_l_[PADL_(char *)]; char * msg_ptr; char msg_ptr_r_[PADR_(char *)];
	char msg_len_l_[PADL_(size_t)]; size_t msg_len; char msg_len_r_[PADR_(size_t)];
	char msg_prio_l_[PADL_(unsigned *)]; unsigned * msg_prio; char msg_prio_r_[PADR_(unsigned *)];
	char abs_timeout_l_[PADL_(const struct timespec *)]; const struct timespec * abs_timeout; char abs_timeout_r_[PADR_(const struct timespec *)];
};
struct freebsd64_kmq_timedsend_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char msg_ptr_l_[PADL_(const char *)]; const char * msg_ptr; char msg_ptr_r_[PADR_(const char *)];
	char msg_len_l_[PADL_(size_t)]; size_t msg_len; char msg_len_r_[PADR_(size_t)];
	char msg_prio_l_[PADL_(unsigned)]; unsigned msg_prio; char msg_prio_r_[PADR_(unsigned)];
	char abs_timeout_l_[PADL_(const struct timespec *)]; const struct timespec * abs_timeout; char abs_timeout_r_[PADR_(const struct timespec *)];
};
struct freebsd64_kmq_notify_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char sigev_l_[PADL_(const struct sigevent64 *)]; const struct sigevent64 * sigev; char sigev_r_[PADR_(const struct sigevent64 *)];
};
struct freebsd64_kmq_unlink_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_abort2_args {
	char why_l_[PADL_(const char *)]; const char * why; char why_r_[PADR_(const char *)];
	char nargs_l_[PADL_(int)]; int nargs; char nargs_r_[PADR_(int)];
	char args_l_[PADL_(void **)]; void ** args; char args_r_[PADR_(void **)];
};
struct freebsd64_thr_set_name_args {
	char id_l_[PADL_(long)]; long id; char id_r_[PADR_(long)];
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
};
struct freebsd64_aio_fsync_args {
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char aiocbp_l_[PADL_(struct aiocb64 *)]; struct aiocb64 * aiocbp; char aiocbp_r_[PADR_(struct aiocb64 *)];
};
struct freebsd64_rtprio_thread_args {
	char function_l_[PADL_(int)]; int function; char function_r_[PADR_(int)];
	char lwpid_l_[PADL_(lwpid_t)]; lwpid_t lwpid; char lwpid_r_[PADR_(lwpid_t)];
	char rtp_l_[PADL_(struct rtprio *)]; struct rtprio * rtp; char rtp_r_[PADR_(struct rtprio *)];
};
struct freebsd64_sctp_generic_sendmsg_args {
	char sd_l_[PADL_(int)]; int sd; char sd_r_[PADR_(int)];
	char msg_l_[PADL_(void *)]; void * msg; char msg_r_[PADR_(void *)];
	char mlen_l_[PADL_(int)]; int mlen; char mlen_r_[PADR_(int)];
	char to_l_[PADL_(const struct sockaddr *)]; const struct sockaddr * to; char to_r_[PADR_(const struct sockaddr *)];
	char tolen_l_[PADL_(__socklen_t)]; __socklen_t tolen; char tolen_r_[PADR_(__socklen_t)];
	char sinfo_l_[PADL_(struct sctp_sndrcvinfo *)]; struct sctp_sndrcvinfo * sinfo; char sinfo_r_[PADR_(struct sctp_sndrcvinfo *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_sctp_generic_sendmsg_iov_args {
	char sd_l_[PADL_(int)]; int sd; char sd_r_[PADR_(int)];
	char iov_l_[PADL_(struct iovec64 *)]; struct iovec64 * iov; char iov_r_[PADR_(struct iovec64 *)];
	char iovlen_l_[PADL_(int)]; int iovlen; char iovlen_r_[PADR_(int)];
	char to_l_[PADL_(const struct sockaddr *)]; const struct sockaddr * to; char to_r_[PADR_(const struct sockaddr *)];
	char tolen_l_[PADL_(__socklen_t)]; __socklen_t tolen; char tolen_r_[PADR_(__socklen_t)];
	char sinfo_l_[PADL_(struct sctp_sndrcvinfo *)]; struct sctp_sndrcvinfo * sinfo; char sinfo_r_[PADR_(struct sctp_sndrcvinfo *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_sctp_generic_recvmsg_args {
	char sd_l_[PADL_(int)]; int sd; char sd_r_[PADR_(int)];
	char iov_l_[PADL_(struct iovec64 *)]; struct iovec64 * iov; char iov_r_[PADR_(struct iovec64 *)];
	char iovlen_l_[PADL_(int)]; int iovlen; char iovlen_r_[PADR_(int)];
	char from_l_[PADL_(struct sockaddr *)]; struct sockaddr * from; char from_r_[PADR_(struct sockaddr *)];
	char fromlenaddr_l_[PADL_(__socklen_t *)]; __socklen_t * fromlenaddr; char fromlenaddr_r_[PADR_(__socklen_t *)];
	char sinfo_l_[PADL_(struct sctp_sndrcvinfo *)]; struct sctp_sndrcvinfo * sinfo; char sinfo_r_[PADR_(struct sctp_sndrcvinfo *)];
	char msg_flags_l_[PADL_(int *)]; int * msg_flags; char msg_flags_r_[PADR_(int *)];
};
struct freebsd64_pread_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(void *)]; void * buf; char buf_r_[PADR_(void *)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct freebsd64_pwrite_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(const void *)]; const void * buf; char buf_r_[PADR_(const void *)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct freebsd64_mmap_args {
	char addr_l_[PADL_(void *)]; void * addr; char addr_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char prot_l_[PADL_(int)]; int prot; char prot_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char pos_l_[PADL_(off_t)]; off_t pos; char pos_r_[PADR_(off_t)];
};
struct freebsd64_truncate_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char length_l_[PADL_(off_t)]; off_t length; char length_r_[PADR_(off_t)];
};
struct freebsd64_shm_unlink_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_cpuset_args {
	char setid_l_[PADL_(cpusetid_t *)]; cpusetid_t * setid; char setid_r_[PADR_(cpusetid_t *)];
};
struct freebsd64_cpuset_getid_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char setid_l_[PADL_(cpusetid_t *)]; cpusetid_t * setid; char setid_r_[PADR_(cpusetid_t *)];
};
struct freebsd64_cpuset_getaffinity_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char cpusetsize_l_[PADL_(size_t)]; size_t cpusetsize; char cpusetsize_r_[PADR_(size_t)];
	char mask_l_[PADL_(cpuset_t *)]; cpuset_t * mask; char mask_r_[PADR_(cpuset_t *)];
};
struct freebsd64_cpuset_setaffinity_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char cpusetsize_l_[PADL_(size_t)]; size_t cpusetsize; char cpusetsize_r_[PADR_(size_t)];
	char mask_l_[PADL_(const cpuset_t *)]; const cpuset_t * mask; char mask_r_[PADR_(const cpuset_t *)];
};
struct freebsd64_faccessat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char amode_l_[PADL_(int)]; int amode; char amode_r_[PADR_(int)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd64_fchmodat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd64_fchownat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char uid_l_[PADL_(uid_t)]; uid_t uid; char uid_r_[PADR_(uid_t)];
	char gid_l_[PADL_(gid_t)]; gid_t gid; char gid_r_[PADR_(gid_t)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd64_fexecve_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char argv_l_[PADL_(char **)]; char ** argv; char argv_r_[PADR_(char **)];
	char envv_l_[PADL_(char **)]; char ** envv; char envv_r_[PADR_(char **)];
};
struct freebsd64_futimesat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char times_l_[PADL_(const struct timeval *)]; const struct timeval * times; char times_r_[PADR_(const struct timeval *)];
};
struct freebsd64_linkat_args {
	char fd1_l_[PADL_(int)]; int fd1; char fd1_r_[PADR_(int)];
	char path1_l_[PADL_(const char *)]; const char * path1; char path1_r_[PADR_(const char *)];
	char fd2_l_[PADL_(int)]; int fd2; char fd2_r_[PADR_(int)];
	char path2_l_[PADL_(const char *)]; const char * path2; char path2_r_[PADR_(const char *)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd64_mkdirat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct freebsd64_mkfifoat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct freebsd64_openat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct freebsd64_readlinkat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char bufsize_l_[PADL_(size_t)]; size_t bufsize; char bufsize_r_[PADR_(size_t)];
};
struct freebsd64_renameat_args {
	char oldfd_l_[PADL_(int)]; int oldfd; char oldfd_r_[PADR_(int)];
	char old_l_[PADL_(const char *)]; const char * old; char old_r_[PADR_(const char *)];
	char newfd_l_[PADL_(int)]; int newfd; char newfd_r_[PADR_(int)];
	char new_l_[PADL_(const char *)]; const char * new; char new_r_[PADR_(const char *)];
};
struct freebsd64_symlinkat_args {
	char path1_l_[PADL_(const char *)]; const char * path1; char path1_r_[PADR_(const char *)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path2_l_[PADL_(const char *)]; const char * path2; char path2_r_[PADR_(const char *)];
};
struct freebsd64_unlinkat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd64_gssd_syscall_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
};
struct freebsd64_jail_get_args {
	char iovp_l_[PADL_(struct iovec64 *)]; struct iovec64 * iovp; char iovp_r_[PADR_(struct iovec64 *)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_jail_set_args {
	char iovp_l_[PADL_(struct iovec64 *)]; struct iovec64 * iovp; char iovp_r_[PADR_(struct iovec64 *)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64___semctl_args {
	char semid_l_[PADL_(int)]; int semid; char semid_r_[PADR_(int)];
	char semnum_l_[PADL_(int)]; int semnum; char semnum_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char arg_l_[PADL_(union semun64 *)]; union semun64 * arg; char arg_r_[PADR_(union semun64 *)];
};
struct freebsd64_msgctl_args {
	char msqid_l_[PADL_(int)]; int msqid; char msqid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char buf_l_[PADL_(struct msqid_ds64 *)]; struct msqid_ds64 * buf; char buf_r_[PADR_(struct msqid_ds64 *)];
};
struct freebsd64_shmctl_args {
	char shmid_l_[PADL_(int)]; int shmid; char shmid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char buf_l_[PADL_(struct shmid_ds *)]; struct shmid_ds * buf; char buf_r_[PADR_(struct shmid_ds *)];
};
struct freebsd64_lpathconf_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
};
struct freebsd64___cap_rights_get_args {
	char version_l_[PADL_(int)]; int version; char version_r_[PADR_(int)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char rightsp_l_[PADL_(cap_rights_t *)]; cap_rights_t * rightsp; char rightsp_r_[PADR_(cap_rights_t *)];
};
struct freebsd64_cap_getmode_args {
	char modep_l_[PADL_(u_int *)]; u_int * modep; char modep_r_[PADR_(u_int *)];
};
struct freebsd64_pdfork_args {
	char fdp_l_[PADL_(int *)]; int * fdp; char fdp_r_[PADR_(int *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_pdgetpid_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char pidp_l_[PADL_(pid_t *)]; pid_t * pidp; char pidp_r_[PADR_(pid_t *)];
};
struct freebsd64_pselect_args {
	char nd_l_[PADL_(int)]; int nd; char nd_r_[PADR_(int)];
	char in_l_[PADL_(fd_set *)]; fd_set * in; char in_r_[PADR_(fd_set *)];
	char ou_l_[PADL_(fd_set *)]; fd_set * ou; char ou_r_[PADR_(fd_set *)];
	char ex_l_[PADL_(fd_set *)]; fd_set * ex; char ex_r_[PADR_(fd_set *)];
	char ts_l_[PADL_(const struct timespec *)]; const struct timespec * ts; char ts_r_[PADR_(const struct timespec *)];
	char sm_l_[PADL_(const sigset_t *)]; const sigset_t * sm; char sm_r_[PADR_(const sigset_t *)];
};
struct freebsd64_getloginclass_args {
	char namebuf_l_[PADL_(char *)]; char * namebuf; char namebuf_r_[PADR_(char *)];
	char namelen_l_[PADL_(size_t)]; size_t namelen; char namelen_r_[PADR_(size_t)];
};
struct freebsd64_setloginclass_args {
	char namebuf_l_[PADL_(const char *)]; const char * namebuf; char namebuf_r_[PADR_(const char *)];
};
struct freebsd64_rctl_get_racct_args {
	char inbufp_l_[PADL_(const void *)]; const void * inbufp; char inbufp_r_[PADR_(const void *)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void *)]; void * outbufp; char outbufp_r_[PADR_(void *)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct freebsd64_rctl_get_rules_args {
	char inbufp_l_[PADL_(const void *)]; const void * inbufp; char inbufp_r_[PADR_(const void *)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void *)]; void * outbufp; char outbufp_r_[PADR_(void *)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct freebsd64_rctl_get_limits_args {
	char inbufp_l_[PADL_(const void *)]; const void * inbufp; char inbufp_r_[PADR_(const void *)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void *)]; void * outbufp; char outbufp_r_[PADR_(void *)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct freebsd64_rctl_add_rule_args {
	char inbufp_l_[PADL_(const void *)]; const void * inbufp; char inbufp_r_[PADR_(const void *)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void *)]; void * outbufp; char outbufp_r_[PADR_(void *)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct freebsd64_rctl_remove_rule_args {
	char inbufp_l_[PADL_(const void *)]; const void * inbufp; char inbufp_r_[PADR_(const void *)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void *)]; void * outbufp; char outbufp_r_[PADR_(void *)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct freebsd64_wait6_args {
	char idtype_l_[PADL_(idtype_t)]; idtype_t idtype; char idtype_r_[PADR_(idtype_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char status_l_[PADL_(int *)]; int * status; char status_r_[PADR_(int *)];
	char options_l_[PADL_(int)]; int options; char options_r_[PADR_(int)];
	char wrusage_l_[PADL_(struct __wrusage *)]; struct __wrusage * wrusage; char wrusage_r_[PADR_(struct __wrusage *)];
	char info_l_[PADL_(struct siginfo64 *)]; struct siginfo64 * info; char info_r_[PADR_(struct siginfo64 *)];
};
struct freebsd64_cap_rights_limit_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char rightsp_l_[PADL_(cap_rights_t *)]; cap_rights_t * rightsp; char rightsp_r_[PADR_(cap_rights_t *)];
};
struct freebsd64_cap_ioctls_limit_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmds_l_[PADL_(const u_long *)]; const u_long * cmds; char cmds_r_[PADR_(const u_long *)];
	char ncmds_l_[PADL_(size_t)]; size_t ncmds; char ncmds_r_[PADR_(size_t)];
};
struct freebsd64_cap_ioctls_get_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmds_l_[PADL_(u_long *)]; u_long * cmds; char cmds_r_[PADR_(u_long *)];
	char maxcmds_l_[PADL_(size_t)]; size_t maxcmds; char maxcmds_r_[PADR_(size_t)];
};
struct freebsd64_cap_fcntls_get_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char fcntlrightsp_l_[PADL_(uint32_t *)]; uint32_t * fcntlrightsp; char fcntlrightsp_r_[PADR_(uint32_t *)];
};
struct freebsd64_bindat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(const struct sockaddr *)]; const struct sockaddr * name; char name_r_[PADR_(const struct sockaddr *)];
	char namelen_l_[PADL_(__socklen_t)]; __socklen_t namelen; char namelen_r_[PADR_(__socklen_t)];
};
struct freebsd64_connectat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(const struct sockaddr *)]; const struct sockaddr * name; char name_r_[PADR_(const struct sockaddr *)];
	char namelen_l_[PADL_(__socklen_t)]; __socklen_t namelen; char namelen_r_[PADR_(__socklen_t)];
};
struct freebsd64_chflagsat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(u_long)]; u_long flags; char flags_r_[PADR_(u_long)];
	char atflag_l_[PADL_(int)]; int atflag; char atflag_r_[PADR_(int)];
};
struct freebsd64_accept4_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(struct sockaddr *)]; struct sockaddr * name; char name_r_[PADR_(struct sockaddr *)];
	char anamelen_l_[PADL_(__socklen_t *)]; __socklen_t * anamelen; char anamelen_r_[PADR_(__socklen_t *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_pipe2_args {
	char fildes_l_[PADL_(int *)]; int * fildes; char fildes_r_[PADR_(int *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_aio_mlock_args {
	char aiocbp_l_[PADL_(struct aiocb64 *)]; struct aiocb64 * aiocbp; char aiocbp_r_[PADR_(struct aiocb64 *)];
};
struct freebsd64_procctl_args {
	char idtype_l_[PADL_(idtype_t)]; idtype_t idtype; char idtype_r_[PADR_(idtype_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char com_l_[PADL_(int)]; int com; char com_r_[PADR_(int)];
	char data_l_[PADL_(void *)]; void * data; char data_r_[PADR_(void *)];
};
struct freebsd64_ppoll_args {
	char fds_l_[PADL_(struct pollfd *)]; struct pollfd * fds; char fds_r_[PADR_(struct pollfd *)];
	char nfds_l_[PADL_(u_int)]; u_int nfds; char nfds_r_[PADR_(u_int)];
	char ts_l_[PADL_(const struct timespec *)]; const struct timespec * ts; char ts_r_[PADR_(const struct timespec *)];
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
};
struct freebsd64_futimens_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char times_l_[PADL_(const struct timespec *)]; const struct timespec * times; char times_r_[PADR_(const struct timespec *)];
};
struct freebsd64_utimensat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char times_l_[PADL_(const struct timespec *)]; const struct timespec * times; char times_r_[PADR_(const struct timespec *)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd64_fstat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char sb_l_[PADL_(struct stat *)]; struct stat * sb; char sb_r_[PADR_(struct stat *)];
};
struct freebsd64_fstatat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char buf_l_[PADL_(struct stat *)]; struct stat * buf; char buf_r_[PADR_(struct stat *)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd64_fhstat_args {
	char u_fhp_l_[PADL_(const struct fhandle *)]; const struct fhandle * u_fhp; char u_fhp_r_[PADR_(const struct fhandle *)];
	char sb_l_[PADL_(struct stat *)]; struct stat * sb; char sb_r_[PADR_(struct stat *)];
};
struct freebsd64_getdirentries_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char count_l_[PADL_(size_t)]; size_t count; char count_r_[PADR_(size_t)];
	char basep_l_[PADL_(off_t *)]; off_t * basep; char basep_r_[PADR_(off_t *)];
};
struct freebsd64_statfs_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char buf_l_[PADL_(struct statfs *)]; struct statfs * buf; char buf_r_[PADR_(struct statfs *)];
};
struct freebsd64_fstatfs_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(struct statfs *)]; struct statfs * buf; char buf_r_[PADR_(struct statfs *)];
};
struct freebsd64_getfsstat_args {
	char buf_l_[PADL_(struct statfs *)]; struct statfs * buf; char buf_r_[PADR_(struct statfs *)];
	char bufsize_l_[PADL_(long)]; long bufsize; char bufsize_r_[PADR_(long)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};
struct freebsd64_fhstatfs_args {
	char u_fhp_l_[PADL_(const struct fhandle *)]; const struct fhandle * u_fhp; char u_fhp_r_[PADR_(const struct fhandle *)];
	char buf_l_[PADL_(struct statfs *)]; struct statfs * buf; char buf_r_[PADR_(struct statfs *)];
};
struct freebsd64_mknodat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char dev_l_[PADL_(dev_t)]; dev_t dev; char dev_r_[PADR_(dev_t)];
};
struct freebsd64_kevent_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char changelist_l_[PADL_(const struct kevent64 *)]; const struct kevent64 * changelist; char changelist_r_[PADR_(const struct kevent64 *)];
	char nchanges_l_[PADL_(int)]; int nchanges; char nchanges_r_[PADR_(int)];
	char eventlist_l_[PADL_(struct kevent64 *)]; struct kevent64 * eventlist; char eventlist_r_[PADR_(struct kevent64 *)];
	char nevents_l_[PADL_(int)]; int nevents; char nevents_r_[PADR_(int)];
	char timeout_l_[PADL_(const struct timespec *)]; const struct timespec * timeout; char timeout_r_[PADR_(const struct timespec *)];
};
struct freebsd64_cpuset_getdomain_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char domainsetsize_l_[PADL_(size_t)]; size_t domainsetsize; char domainsetsize_r_[PADR_(size_t)];
	char mask_l_[PADL_(domainset_t *)]; domainset_t * mask; char mask_r_[PADR_(domainset_t *)];
	char policy_l_[PADL_(int *)]; int * policy; char policy_r_[PADR_(int *)];
};
struct freebsd64_cpuset_setdomain_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char domainsetsize_l_[PADL_(size_t)]; size_t domainsetsize; char domainsetsize_r_[PADR_(size_t)];
	char mask_l_[PADL_(domainset_t *)]; domainset_t * mask; char mask_r_[PADR_(domainset_t *)];
	char policy_l_[PADL_(int)]; int policy; char policy_r_[PADR_(int)];
};
struct freebsd64_getrandom_args {
	char buf_l_[PADL_(void *)]; void * buf; char buf_r_[PADR_(void *)];
	char buflen_l_[PADL_(size_t)]; size_t buflen; char buflen_r_[PADR_(size_t)];
	char flags_l_[PADL_(unsigned int)]; unsigned int flags; char flags_r_[PADR_(unsigned int)];
};
struct freebsd64_getfhat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(char *)]; char * path; char path_r_[PADR_(char *)];
	char fhp_l_[PADL_(struct fhandle *)]; struct fhandle * fhp; char fhp_r_[PADR_(struct fhandle *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct freebsd64_fhlink_args {
	char fhp_l_[PADL_(struct fhandle *)]; struct fhandle * fhp; char fhp_r_[PADR_(struct fhandle *)];
	char to_l_[PADL_(const char *)]; const char * to; char to_r_[PADR_(const char *)];
};
struct freebsd64_fhlinkat_args {
	char fhp_l_[PADL_(struct fhandle *)]; struct fhandle * fhp; char fhp_r_[PADR_(struct fhandle *)];
	char tofd_l_[PADL_(int)]; int tofd; char tofd_r_[PADR_(int)];
	char to_l_[PADL_(const char *)]; const char * to; char to_r_[PADR_(const char *)];
};
struct freebsd64_fhreadlink_args {
	char fhp_l_[PADL_(struct fhandle *)]; struct fhandle * fhp; char fhp_r_[PADR_(struct fhandle *)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char bufsize_l_[PADL_(size_t)]; size_t bufsize; char bufsize_r_[PADR_(size_t)];
};
struct freebsd64_funlinkat_args {
	char dfd_l_[PADL_(int)]; int dfd; char dfd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd64_copy_file_range_args {
	char infd_l_[PADL_(int)]; int infd; char infd_r_[PADR_(int)];
	char inoffp_l_[PADL_(off_t *)]; off_t * inoffp; char inoffp_r_[PADR_(off_t *)];
	char outfd_l_[PADL_(int)]; int outfd; char outfd_r_[PADR_(int)];
	char outoffp_l_[PADL_(off_t *)]; off_t * outoffp; char outoffp_r_[PADR_(off_t *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(unsigned int)]; unsigned int flags; char flags_r_[PADR_(unsigned int)];
};
struct freebsd64___sysctlbyname_args {
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
	char namelen_l_[PADL_(size_t)]; size_t namelen; char namelen_r_[PADR_(size_t)];
	char old_l_[PADL_(void *)]; void * old; char old_r_[PADR_(void *)];
	char oldlenp_l_[PADL_(size_t *)]; size_t * oldlenp; char oldlenp_r_[PADR_(size_t *)];
	char new_l_[PADL_(void *)]; void * new; char new_r_[PADR_(void *)];
	char newlen_l_[PADL_(size_t)]; size_t newlen; char newlen_r_[PADR_(size_t)];
};
struct freebsd64_shm_open2_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char shmflags_l_[PADL_(int)]; int shmflags; char shmflags_r_[PADR_(int)];
	char name_l_[PADL_(const char *)]; const char * name; char name_r_[PADR_(const char *)];
};
struct freebsd64_shm_rename_args {
	char path_from_l_[PADL_(const char *)]; const char * path_from; char path_from_r_[PADR_(const char *)];
	char path_to_l_[PADL_(const char *)]; const char * path_to; char path_to_r_[PADR_(const char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
int	freebsd64_read(struct thread *, struct freebsd64_read_args *);
int	freebsd64_write(struct thread *, struct freebsd64_write_args *);
int	freebsd64_open(struct thread *, struct freebsd64_open_args *);
int	freebsd64_wait4(struct thread *, struct freebsd64_wait4_args *);
int	freebsd64_link(struct thread *, struct freebsd64_link_args *);
int	freebsd64_unlink(struct thread *, struct freebsd64_unlink_args *);
int	freebsd64_chdir(struct thread *, struct freebsd64_chdir_args *);
int	freebsd64_chmod(struct thread *, struct freebsd64_chmod_args *);
int	freebsd64_chown(struct thread *, struct freebsd64_chown_args *);
int	freebsd64_break(struct thread *, struct freebsd64_break_args *);
int	freebsd64_mount(struct thread *, struct freebsd64_mount_args *);
int	freebsd64_unmount(struct thread *, struct freebsd64_unmount_args *);
int	freebsd64_ptrace(struct thread *, struct freebsd64_ptrace_args *);
int	freebsd64_recvmsg(struct thread *, struct freebsd64_recvmsg_args *);
int	freebsd64_sendmsg(struct thread *, struct freebsd64_sendmsg_args *);
int	freebsd64_recvfrom(struct thread *, struct freebsd64_recvfrom_args *);
int	freebsd64_accept(struct thread *, struct freebsd64_accept_args *);
int	freebsd64_getpeername(struct thread *, struct freebsd64_getpeername_args *);
int	freebsd64_getsockname(struct thread *, struct freebsd64_getsockname_args *);
int	freebsd64_access(struct thread *, struct freebsd64_access_args *);
int	freebsd64_chflags(struct thread *, struct freebsd64_chflags_args *);
int	freebsd64_profil(struct thread *, struct freebsd64_profil_args *);
int	freebsd64_ktrace(struct thread *, struct freebsd64_ktrace_args *);
int	freebsd64_getlogin(struct thread *, struct freebsd64_getlogin_args *);
int	freebsd64_setlogin(struct thread *, struct freebsd64_setlogin_args *);
int	freebsd64_acct(struct thread *, struct freebsd64_acct_args *);
int	freebsd64_sigaltstack(struct thread *, struct freebsd64_sigaltstack_args *);
int	freebsd64_ioctl(struct thread *, struct freebsd64_ioctl_args *);
int	freebsd64_revoke(struct thread *, struct freebsd64_revoke_args *);
int	freebsd64_symlink(struct thread *, struct freebsd64_symlink_args *);
int	freebsd64_readlink(struct thread *, struct freebsd64_readlink_args *);
int	freebsd64_execve(struct thread *, struct freebsd64_execve_args *);
int	freebsd64_chroot(struct thread *, struct freebsd64_chroot_args *);
int	freebsd64_msync(struct thread *, struct freebsd64_msync_args *);
int	freebsd64_munmap(struct thread *, struct freebsd64_munmap_args *);
int	freebsd64_mprotect(struct thread *, struct freebsd64_mprotect_args *);
int	freebsd64_madvise(struct thread *, struct freebsd64_madvise_args *);
int	freebsd64_mincore(struct thread *, struct freebsd64_mincore_args *);
int	freebsd64_getgroups(struct thread *, struct freebsd64_getgroups_args *);
int	freebsd64_setgroups(struct thread *, struct freebsd64_setgroups_args *);
int	freebsd64_setitimer(struct thread *, struct freebsd64_setitimer_args *);
int	freebsd64_swapon(struct thread *, struct freebsd64_swapon_args *);
int	freebsd64_getitimer(struct thread *, struct freebsd64_getitimer_args *);
int	freebsd64_fcntl(struct thread *, struct freebsd64_fcntl_args *);
int	freebsd64_select(struct thread *, struct freebsd64_select_args *);
int	freebsd64_connect(struct thread *, struct freebsd64_connect_args *);
int	freebsd64_bind(struct thread *, struct freebsd64_bind_args *);
int	freebsd64_setsockopt(struct thread *, struct freebsd64_setsockopt_args *);
int	freebsd64_gettimeofday(struct thread *, struct freebsd64_gettimeofday_args *);
int	freebsd64_getrusage(struct thread *, struct freebsd64_getrusage_args *);
int	freebsd64_getsockopt(struct thread *, struct freebsd64_getsockopt_args *);
int	freebsd64_readv(struct thread *, struct freebsd64_readv_args *);
int	freebsd64_writev(struct thread *, struct freebsd64_writev_args *);
int	freebsd64_settimeofday(struct thread *, struct freebsd64_settimeofday_args *);
int	freebsd64_rename(struct thread *, struct freebsd64_rename_args *);
int	freebsd64_mkfifo(struct thread *, struct freebsd64_mkfifo_args *);
int	freebsd64_sendto(struct thread *, struct freebsd64_sendto_args *);
int	freebsd64_socketpair(struct thread *, struct freebsd64_socketpair_args *);
int	freebsd64_mkdir(struct thread *, struct freebsd64_mkdir_args *);
int	freebsd64_rmdir(struct thread *, struct freebsd64_rmdir_args *);
int	freebsd64_utimes(struct thread *, struct freebsd64_utimes_args *);
int	freebsd64_adjtime(struct thread *, struct freebsd64_adjtime_args *);
int	freebsd64_quotactl(struct thread *, struct freebsd64_quotactl_args *);
int	freebsd64_nlm_syscall(struct thread *, struct freebsd64_nlm_syscall_args *);
int	freebsd64_nfssvc(struct thread *, struct freebsd64_nfssvc_args *);
int	freebsd64_lgetfh(struct thread *, struct freebsd64_lgetfh_args *);
int	freebsd64_getfh(struct thread *, struct freebsd64_getfh_args *);
int	freebsd64_sysarch(struct thread *, struct freebsd64_sysarch_args *);
int	freebsd64_rtprio(struct thread *, struct freebsd64_rtprio_args *);
int	freebsd64_semsys(struct thread *, struct freebsd64_semsys_args *);
int	freebsd64_msgsys(struct thread *, struct freebsd64_msgsys_args *);
int	freebsd64_shmsys(struct thread *, struct freebsd64_shmsys_args *);
int	freebsd64_ntp_adjtime(struct thread *, struct freebsd64_ntp_adjtime_args *);
int	freebsd64_pathconf(struct thread *, struct freebsd64_pathconf_args *);
int	freebsd64_getrlimit(struct thread *, struct freebsd64___getrlimit_args *);
int	freebsd64_setrlimit(struct thread *, struct freebsd64___setrlimit_args *);
int	freebsd64___sysctl(struct thread *, struct freebsd64___sysctl_args *);
int	freebsd64_mlock(struct thread *, struct freebsd64_mlock_args *);
int	freebsd64_munlock(struct thread *, struct freebsd64_munlock_args *);
int	freebsd64_undelete(struct thread *, struct freebsd64_undelete_args *);
int	freebsd64_futimes(struct thread *, struct freebsd64_futimes_args *);
int	freebsd64_poll(struct thread *, struct freebsd64_poll_args *);
int	freebsd64_semop(struct thread *, struct freebsd64_semop_args *);
int	freebsd64_msgsnd(struct thread *, struct freebsd64_msgsnd_args *);
int	freebsd64_msgrcv(struct thread *, struct freebsd64_msgrcv_args *);
int	freebsd64_shmat(struct thread *, struct freebsd64_shmat_args *);
int	freebsd64_shmdt(struct thread *, struct freebsd64_shmdt_args *);
int	freebsd64_clock_gettime(struct thread *, struct freebsd64_clock_gettime_args *);
int	freebsd64_clock_settime(struct thread *, struct freebsd64_clock_settime_args *);
int	freebsd64_clock_getres(struct thread *, struct freebsd64_clock_getres_args *);
int	freebsd64_ktimer_create(struct thread *, struct freebsd64_ktimer_create_args *);
int	freebsd64_ktimer_settime(struct thread *, struct freebsd64_ktimer_settime_args *);
int	freebsd64_ktimer_gettime(struct thread *, struct freebsd64_ktimer_gettime_args *);
int	freebsd64_nanosleep(struct thread *, struct freebsd64_nanosleep_args *);
int	freebsd64_ffclock_getcounter(struct thread *, struct freebsd64_ffclock_getcounter_args *);
int	freebsd64_ffclock_setestimate(struct thread *, struct freebsd64_ffclock_setestimate_args *);
int	freebsd64_ffclock_getestimate(struct thread *, struct freebsd64_ffclock_getestimate_args *);
int	freebsd64_clock_nanosleep(struct thread *, struct freebsd64_clock_nanosleep_args *);
int	freebsd64_clock_getcpuclockid2(struct thread *, struct freebsd64_clock_getcpuclockid2_args *);
int	freebsd64_ntp_gettime(struct thread *, struct freebsd64_ntp_gettime_args *);
int	freebsd64_minherit(struct thread *, struct freebsd64_minherit_args *);
int	freebsd64_lchown(struct thread *, struct freebsd64_lchown_args *);
int	freebsd64_aio_read(struct thread *, struct freebsd64_aio_read_args *);
int	freebsd64_aio_write(struct thread *, struct freebsd64_aio_write_args *);
int	freebsd64_lio_listio(struct thread *, struct freebsd64_lio_listio_args *);
int	freebsd64_kbounce(struct thread *, struct freebsd64_kbounce_args *);
int	freebsd64_lchmod(struct thread *, struct freebsd64_lchmod_args *);
int	freebsd64_lutimes(struct thread *, struct freebsd64_lutimes_args *);
int	freebsd64_preadv(struct thread *, struct freebsd64_preadv_args *);
int	freebsd64_pwritev(struct thread *, struct freebsd64_pwritev_args *);
int	freebsd64_fhopen(struct thread *, struct freebsd64_fhopen_args *);
int	freebsd64_modstat(struct thread *, struct freebsd64_modstat_args *);
int	freebsd64_modfind(struct thread *, struct freebsd64_modfind_args *);
int	freebsd64_kldload(struct thread *, struct freebsd64_kldload_args *);
int	freebsd64_kldfind(struct thread *, struct freebsd64_kldfind_args *);
int	freebsd64_kldstat(struct thread *, struct freebsd64_kldstat_args *);
int	freebsd64_aio_return(struct thread *, struct freebsd64_aio_return_args *);
int	freebsd64_aio_suspend(struct thread *, struct freebsd64_aio_suspend_args *);
int	freebsd64_aio_cancel(struct thread *, struct freebsd64_aio_cancel_args *);
int	freebsd64_aio_error(struct thread *, struct freebsd64_aio_error_args *);
int	freebsd64___getcwd(struct thread *, struct freebsd64___getcwd_args *);
int	freebsd64_sched_setparam(struct thread *, struct freebsd64_sched_setparam_args *);
int	freebsd64_sched_getparam(struct thread *, struct freebsd64_sched_getparam_args *);
int	freebsd64_sched_setscheduler(struct thread *, struct freebsd64_sched_setscheduler_args *);
int	freebsd64_sched_rr_get_interval(struct thread *, struct freebsd64_sched_rr_get_interval_args *);
int	freebsd64_utrace(struct thread *, struct freebsd64_utrace_args *);
int	freebsd64_kldsym(struct thread *, struct freebsd64_kldsym_args *);
int	freebsd64_jail(struct thread *, struct freebsd64_jail_args *);
int	freebsd64_nnpfs_syscall(struct thread *, struct freebsd64_nnpfs_syscall_args *);
int	freebsd64_sigprocmask(struct thread *, struct freebsd64_sigprocmask_args *);
int	freebsd64_sigsuspend(struct thread *, struct freebsd64_sigsuspend_args *);
int	freebsd64_sigpending(struct thread *, struct freebsd64_sigpending_args *);
int	freebsd64_sigtimedwait(struct thread *, struct freebsd64_sigtimedwait_args *);
int	freebsd64_sigwaitinfo(struct thread *, struct freebsd64_sigwaitinfo_args *);
int	freebsd64___acl_get_file(struct thread *, struct freebsd64___acl_get_file_args *);
int	freebsd64___acl_set_file(struct thread *, struct freebsd64___acl_set_file_args *);
int	freebsd64___acl_get_fd(struct thread *, struct freebsd64___acl_get_fd_args *);
int	freebsd64___acl_set_fd(struct thread *, struct freebsd64___acl_set_fd_args *);
int	freebsd64___acl_delete_file(struct thread *, struct freebsd64___acl_delete_file_args *);
int	freebsd64___acl_aclcheck_file(struct thread *, struct freebsd64___acl_aclcheck_file_args *);
int	freebsd64___acl_aclcheck_fd(struct thread *, struct freebsd64___acl_aclcheck_fd_args *);
int	freebsd64_extattrctl(struct thread *, struct freebsd64_extattrctl_args *);
int	freebsd64_extattr_set_file(struct thread *, struct freebsd64_extattr_set_file_args *);
int	freebsd64_extattr_get_file(struct thread *, struct freebsd64_extattr_get_file_args *);
int	freebsd64_extattr_delete_file(struct thread *, struct freebsd64_extattr_delete_file_args *);
int	freebsd64_aio_waitcomplete(struct thread *, struct freebsd64_aio_waitcomplete_args *);
int	freebsd64_getresuid(struct thread *, struct freebsd64_getresuid_args *);
int	freebsd64_getresgid(struct thread *, struct freebsd64_getresgid_args *);
int	freebsd64_extattr_set_fd(struct thread *, struct freebsd64_extattr_set_fd_args *);
int	freebsd64_extattr_get_fd(struct thread *, struct freebsd64_extattr_get_fd_args *);
int	freebsd64_extattr_delete_fd(struct thread *, struct freebsd64_extattr_delete_fd_args *);
int	freebsd64_eaccess(struct thread *, struct freebsd64_eaccess_args *);
int	freebsd64_nmount(struct thread *, struct freebsd64_nmount_args *);
int	freebsd64___mac_get_proc(struct thread *, struct freebsd64___mac_get_proc_args *);
int	freebsd64___mac_set_proc(struct thread *, struct freebsd64___mac_set_proc_args *);
int	freebsd64___mac_get_fd(struct thread *, struct freebsd64___mac_get_fd_args *);
int	freebsd64___mac_get_file(struct thread *, struct freebsd64___mac_get_file_args *);
int	freebsd64___mac_set_fd(struct thread *, struct freebsd64___mac_set_fd_args *);
int	freebsd64___mac_set_file(struct thread *, struct freebsd64___mac_set_file_args *);
int	freebsd64_kenv(struct thread *, struct freebsd64_kenv_args *);
int	freebsd64_lchflags(struct thread *, struct freebsd64_lchflags_args *);
int	freebsd64_uuidgen(struct thread *, struct freebsd64_uuidgen_args *);
int	freebsd64_sendfile(struct thread *, struct freebsd64_sendfile_args *);
int	freebsd64_mac_syscall(struct thread *, struct freebsd64_mac_syscall_args *);
int	freebsd64_ksem_init(struct thread *, struct freebsd64_ksem_init_args *);
int	freebsd64_ksem_open(struct thread *, struct freebsd64_ksem_open_args *);
int	freebsd64_ksem_unlink(struct thread *, struct freebsd64_ksem_unlink_args *);
int	freebsd64_ksem_getvalue(struct thread *, struct freebsd64_ksem_getvalue_args *);
int	freebsd64___mac_get_pid(struct thread *, struct freebsd64___mac_get_pid_args *);
int	freebsd64___mac_get_link(struct thread *, struct freebsd64___mac_get_link_args *);
int	freebsd64___mac_set_link(struct thread *, struct freebsd64___mac_set_link_args *);
int	freebsd64_extattr_set_link(struct thread *, struct freebsd64_extattr_set_link_args *);
int	freebsd64_extattr_get_link(struct thread *, struct freebsd64_extattr_get_link_args *);
int	freebsd64_extattr_delete_link(struct thread *, struct freebsd64_extattr_delete_link_args *);
int	freebsd64___mac_execve(struct thread *, struct freebsd64___mac_execve_args *);
int	freebsd64_sigaction(struct thread *, struct freebsd64_sigaction_args *);
int	freebsd64_sigreturn(struct thread *, struct freebsd64_sigreturn_args *);
int	freebsd64_getcontext(struct thread *, struct freebsd64_getcontext_args *);
int	freebsd64_setcontext(struct thread *, struct freebsd64_setcontext_args *);
int	freebsd64_swapcontext(struct thread *, struct freebsd64_swapcontext_args *);
int	freebsd64_swapoff(struct thread *, struct freebsd64_swapoff_args *);
int	freebsd64___acl_get_link(struct thread *, struct freebsd64___acl_get_link_args *);
int	freebsd64___acl_set_link(struct thread *, struct freebsd64___acl_set_link_args *);
int	freebsd64___acl_delete_link(struct thread *, struct freebsd64___acl_delete_link_args *);
int	freebsd64___acl_aclcheck_link(struct thread *, struct freebsd64___acl_aclcheck_link_args *);
int	freebsd64_sigwait(struct thread *, struct freebsd64_sigwait_args *);
int	freebsd64_thr_create(struct thread *, struct freebsd64_thr_create_args *);
int	freebsd64_thr_exit(struct thread *, struct freebsd64_thr_exit_args *);
int	freebsd64_thr_self(struct thread *, struct freebsd64_thr_self_args *);
int	freebsd64_extattr_list_fd(struct thread *, struct freebsd64_extattr_list_fd_args *);
int	freebsd64_extattr_list_file(struct thread *, struct freebsd64_extattr_list_file_args *);
int	freebsd64_extattr_list_link(struct thread *, struct freebsd64_extattr_list_link_args *);
int	freebsd64_ksem_timedwait(struct thread *, struct freebsd64_ksem_timedwait_args *);
int	freebsd64_thr_suspend(struct thread *, struct freebsd64_thr_suspend_args *);
int	freebsd64_audit(struct thread *, struct freebsd64_audit_args *);
int	freebsd64_auditon(struct thread *, struct freebsd64_auditon_args *);
int	freebsd64_getauid(struct thread *, struct freebsd64_getauid_args *);
int	freebsd64_setauid(struct thread *, struct freebsd64_setauid_args *);
int	freebsd64_getaudit(struct thread *, struct freebsd64_getaudit_args *);
int	freebsd64_setaudit(struct thread *, struct freebsd64_setaudit_args *);
int	freebsd64_getaudit_addr(struct thread *, struct freebsd64_getaudit_addr_args *);
int	freebsd64_setaudit_addr(struct thread *, struct freebsd64_setaudit_addr_args *);
int	freebsd64_auditctl(struct thread *, struct freebsd64_auditctl_args *);
int	freebsd64__umtx_op(struct thread *, struct freebsd64__umtx_op_args *);
int	freebsd64_thr_new(struct thread *, struct freebsd64_thr_new_args *);
int	freebsd64_sigqueue(struct thread *, struct freebsd64_sigqueue_args *);
int	freebsd64_kmq_open(struct thread *, struct freebsd64_kmq_open_args *);
int	freebsd64_kmq_setattr(struct thread *, struct freebsd64_kmq_setattr_args *);
int	freebsd64_kmq_timedreceive(struct thread *, struct freebsd64_kmq_timedreceive_args *);
int	freebsd64_kmq_timedsend(struct thread *, struct freebsd64_kmq_timedsend_args *);
int	freebsd64_kmq_notify(struct thread *, struct freebsd64_kmq_notify_args *);
int	freebsd64_kmq_unlink(struct thread *, struct freebsd64_kmq_unlink_args *);
int	freebsd64_abort2(struct thread *, struct freebsd64_abort2_args *);
int	freebsd64_thr_set_name(struct thread *, struct freebsd64_thr_set_name_args *);
int	freebsd64_aio_fsync(struct thread *, struct freebsd64_aio_fsync_args *);
int	freebsd64_rtprio_thread(struct thread *, struct freebsd64_rtprio_thread_args *);
int	freebsd64_sctp_generic_sendmsg(struct thread *, struct freebsd64_sctp_generic_sendmsg_args *);
int	freebsd64_sctp_generic_sendmsg_iov(struct thread *, struct freebsd64_sctp_generic_sendmsg_iov_args *);
int	freebsd64_sctp_generic_recvmsg(struct thread *, struct freebsd64_sctp_generic_recvmsg_args *);
int	freebsd64_pread(struct thread *, struct freebsd64_pread_args *);
int	freebsd64_pwrite(struct thread *, struct freebsd64_pwrite_args *);
int	freebsd64_mmap(struct thread *, struct freebsd64_mmap_args *);
int	freebsd64_truncate(struct thread *, struct freebsd64_truncate_args *);
int	freebsd64_shm_unlink(struct thread *, struct freebsd64_shm_unlink_args *);
int	freebsd64_cpuset(struct thread *, struct freebsd64_cpuset_args *);
int	freebsd64_cpuset_getid(struct thread *, struct freebsd64_cpuset_getid_args *);
int	freebsd64_cpuset_getaffinity(struct thread *, struct freebsd64_cpuset_getaffinity_args *);
int	freebsd64_cpuset_setaffinity(struct thread *, struct freebsd64_cpuset_setaffinity_args *);
int	freebsd64_faccessat(struct thread *, struct freebsd64_faccessat_args *);
int	freebsd64_fchmodat(struct thread *, struct freebsd64_fchmodat_args *);
int	freebsd64_fchownat(struct thread *, struct freebsd64_fchownat_args *);
int	freebsd64_fexecve(struct thread *, struct freebsd64_fexecve_args *);
int	freebsd64_futimesat(struct thread *, struct freebsd64_futimesat_args *);
int	freebsd64_linkat(struct thread *, struct freebsd64_linkat_args *);
int	freebsd64_mkdirat(struct thread *, struct freebsd64_mkdirat_args *);
int	freebsd64_mkfifoat(struct thread *, struct freebsd64_mkfifoat_args *);
int	freebsd64_openat(struct thread *, struct freebsd64_openat_args *);
int	freebsd64_readlinkat(struct thread *, struct freebsd64_readlinkat_args *);
int	freebsd64_renameat(struct thread *, struct freebsd64_renameat_args *);
int	freebsd64_symlinkat(struct thread *, struct freebsd64_symlinkat_args *);
int	freebsd64_unlinkat(struct thread *, struct freebsd64_unlinkat_args *);
int	freebsd64_gssd_syscall(struct thread *, struct freebsd64_gssd_syscall_args *);
int	freebsd64_jail_get(struct thread *, struct freebsd64_jail_get_args *);
int	freebsd64_jail_set(struct thread *, struct freebsd64_jail_set_args *);
int	freebsd64___semctl(struct thread *, struct freebsd64___semctl_args *);
int	freebsd64_msgctl(struct thread *, struct freebsd64_msgctl_args *);
int	freebsd64_shmctl(struct thread *, struct freebsd64_shmctl_args *);
int	freebsd64_lpathconf(struct thread *, struct freebsd64_lpathconf_args *);
int	freebsd64___cap_rights_get(struct thread *, struct freebsd64___cap_rights_get_args *);
int	freebsd64_cap_getmode(struct thread *, struct freebsd64_cap_getmode_args *);
int	freebsd64_pdfork(struct thread *, struct freebsd64_pdfork_args *);
int	freebsd64_pdgetpid(struct thread *, struct freebsd64_pdgetpid_args *);
int	freebsd64_pselect(struct thread *, struct freebsd64_pselect_args *);
int	freebsd64_getloginclass(struct thread *, struct freebsd64_getloginclass_args *);
int	freebsd64_setloginclass(struct thread *, struct freebsd64_setloginclass_args *);
int	freebsd64_rctl_get_racct(struct thread *, struct freebsd64_rctl_get_racct_args *);
int	freebsd64_rctl_get_rules(struct thread *, struct freebsd64_rctl_get_rules_args *);
int	freebsd64_rctl_get_limits(struct thread *, struct freebsd64_rctl_get_limits_args *);
int	freebsd64_rctl_add_rule(struct thread *, struct freebsd64_rctl_add_rule_args *);
int	freebsd64_rctl_remove_rule(struct thread *, struct freebsd64_rctl_remove_rule_args *);
int	freebsd64_wait6(struct thread *, struct freebsd64_wait6_args *);
int	freebsd64_cap_rights_limit(struct thread *, struct freebsd64_cap_rights_limit_args *);
int	freebsd64_cap_ioctls_limit(struct thread *, struct freebsd64_cap_ioctls_limit_args *);
int	freebsd64_cap_ioctls_get(struct thread *, struct freebsd64_cap_ioctls_get_args *);
int	freebsd64_cap_fcntls_get(struct thread *, struct freebsd64_cap_fcntls_get_args *);
int	freebsd64_bindat(struct thread *, struct freebsd64_bindat_args *);
int	freebsd64_connectat(struct thread *, struct freebsd64_connectat_args *);
int	freebsd64_chflagsat(struct thread *, struct freebsd64_chflagsat_args *);
int	freebsd64_accept4(struct thread *, struct freebsd64_accept4_args *);
int	freebsd64_pipe2(struct thread *, struct freebsd64_pipe2_args *);
int	freebsd64_aio_mlock(struct thread *, struct freebsd64_aio_mlock_args *);
int	freebsd64_procctl(struct thread *, struct freebsd64_procctl_args *);
int	freebsd64_ppoll(struct thread *, struct freebsd64_ppoll_args *);
int	freebsd64_futimens(struct thread *, struct freebsd64_futimens_args *);
int	freebsd64_utimensat(struct thread *, struct freebsd64_utimensat_args *);
int	freebsd64_fstat(struct thread *, struct freebsd64_fstat_args *);
int	freebsd64_fstatat(struct thread *, struct freebsd64_fstatat_args *);
int	freebsd64_fhstat(struct thread *, struct freebsd64_fhstat_args *);
int	freebsd64_getdirentries(struct thread *, struct freebsd64_getdirentries_args *);
int	freebsd64_statfs(struct thread *, struct freebsd64_statfs_args *);
int	freebsd64_fstatfs(struct thread *, struct freebsd64_fstatfs_args *);
int	freebsd64_getfsstat(struct thread *, struct freebsd64_getfsstat_args *);
int	freebsd64_fhstatfs(struct thread *, struct freebsd64_fhstatfs_args *);
int	freebsd64_mknodat(struct thread *, struct freebsd64_mknodat_args *);
int	freebsd64_kevent(struct thread *, struct freebsd64_kevent_args *);
int	freebsd64_cpuset_getdomain(struct thread *, struct freebsd64_cpuset_getdomain_args *);
int	freebsd64_cpuset_setdomain(struct thread *, struct freebsd64_cpuset_setdomain_args *);
int	freebsd64_getrandom(struct thread *, struct freebsd64_getrandom_args *);
int	freebsd64_getfhat(struct thread *, struct freebsd64_getfhat_args *);
int	freebsd64_fhlink(struct thread *, struct freebsd64_fhlink_args *);
int	freebsd64_fhlinkat(struct thread *, struct freebsd64_fhlinkat_args *);
int	freebsd64_fhreadlink(struct thread *, struct freebsd64_fhreadlink_args *);
int	freebsd64_funlinkat(struct thread *, struct freebsd64_funlinkat_args *);
int	freebsd64_copy_file_range(struct thread *, struct freebsd64_copy_file_range_args *);
int	freebsd64___sysctlbyname(struct thread *, struct freebsd64___sysctlbyname_args *);
int	freebsd64_shm_open2(struct thread *, struct freebsd64_shm_open2_args *);
int	freebsd64_shm_rename(struct thread *, struct freebsd64_shm_rename_args *);

#ifdef COMPAT_43


#endif /* COMPAT_43 */


#ifdef COMPAT_FREEBSD4


#endif /* COMPAT_FREEBSD4 */


#ifdef COMPAT_FREEBSD6

struct freebsd6_freebsd64_pread_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(void *)]; void * buf; char buf_r_[PADR_(void *)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
	char pad_l_[PADL_(int)]; int pad; char pad_r_[PADR_(int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct freebsd6_freebsd64_pwrite_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(const void *)]; const void * buf; char buf_r_[PADR_(const void *)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
	char pad_l_[PADL_(int)]; int pad; char pad_r_[PADR_(int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct freebsd6_freebsd64_mmap_args {
	char addr_l_[PADL_(void *)]; void * addr; char addr_r_[PADR_(void *)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char prot_l_[PADL_(int)]; int prot; char prot_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char pad_l_[PADL_(int)]; int pad; char pad_r_[PADR_(int)];
	char pos_l_[PADL_(off_t)]; off_t pos; char pos_r_[PADR_(off_t)];
};
struct freebsd6_freebsd64_truncate_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char pad_l_[PADL_(int)]; int pad; char pad_r_[PADR_(int)];
	char length_l_[PADL_(off_t)]; off_t length; char length_r_[PADR_(off_t)];
};
struct freebsd6_freebsd64_aio_read_args {
	char aiocbp_l_[PADL_(struct oaiocb64 *)]; struct oaiocb64 * aiocbp; char aiocbp_r_[PADR_(struct oaiocb64 *)];
};
struct freebsd6_freebsd64_aio_write_args {
	char aiocbp_l_[PADL_(struct oaiocb64 *)]; struct oaiocb64 * aiocbp; char aiocbp_r_[PADR_(struct oaiocb64 *)];
};
struct freebsd6_freebsd64_lio_listio_args {
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
	char acb_list_l_[PADL_(struct oaiocb64 *const *)]; struct oaiocb64 *const * acb_list; char acb_list_r_[PADR_(struct oaiocb64 *const *)];
	char nent_l_[PADL_(int)]; int nent; char nent_r_[PADR_(int)];
	char sig_l_[PADL_(struct osigevent64 *)]; struct osigevent64 * sig; char sig_r_[PADR_(struct osigevent64 *)];
};
int	freebsd6_freebsd64_pread(struct thread *, struct freebsd6_freebsd64_pread_args *);
int	freebsd6_freebsd64_pwrite(struct thread *, struct freebsd6_freebsd64_pwrite_args *);
int	freebsd6_freebsd64_mmap(struct thread *, struct freebsd6_freebsd64_mmap_args *);
int	freebsd6_freebsd64_truncate(struct thread *, struct freebsd6_freebsd64_truncate_args *);
int	freebsd6_freebsd64_aio_read(struct thread *, struct freebsd6_freebsd64_aio_read_args *);
int	freebsd6_freebsd64_aio_write(struct thread *, struct freebsd6_freebsd64_aio_write_args *);
int	freebsd6_freebsd64_lio_listio(struct thread *, struct freebsd6_freebsd64_lio_listio_args *);

#endif /* COMPAT_FREEBSD6 */


#ifdef COMPAT_FREEBSD7

struct freebsd7_freebsd64___semctl_args {
	char semid_l_[PADL_(int)]; int semid; char semid_r_[PADR_(int)];
	char semnum_l_[PADL_(int)]; int semnum; char semnum_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char arg_l_[PADL_(union semun_old64 *)]; union semun_old64 * arg; char arg_r_[PADR_(union semun_old64 *)];
};
struct freebsd7_freebsd64_msgctl_args {
	char msqid_l_[PADL_(int)]; int msqid; char msqid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char buf_l_[PADL_(struct msqid_ds_old64 *)]; struct msqid_ds_old64 * buf; char buf_r_[PADR_(struct msqid_ds_old64 *)];
};
struct freebsd7_freebsd64_shmctl_args {
	char shmid_l_[PADL_(int)]; int shmid; char shmid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char buf_l_[PADL_(struct shmid_ds_old64 *)]; struct shmid_ds_old64 * buf; char buf_r_[PADR_(struct shmid_ds_old64 *)];
};
int	freebsd7_freebsd64___semctl(struct thread *, struct freebsd7_freebsd64___semctl_args *);
int	freebsd7_freebsd64_msgctl(struct thread *, struct freebsd7_freebsd64_msgctl_args *);
int	freebsd7_freebsd64_shmctl(struct thread *, struct freebsd7_freebsd64_shmctl_args *);

#endif /* COMPAT_FREEBSD7 */


#ifdef COMPAT_FREEBSD10


#endif /* COMPAT_FREEBSD10 */


#ifdef COMPAT_FREEBSD11

struct freebsd11_freebsd64_mknod_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
	char dev_l_[PADL_(uint32_t)]; uint32_t dev; char dev_r_[PADR_(uint32_t)];
};
struct freebsd11_freebsd64_stat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct freebsd11_stat *)]; struct freebsd11_stat * ub; char ub_r_[PADR_(struct freebsd11_stat *)];
};
struct freebsd11_freebsd64_fstat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char sb_l_[PADL_(struct freebsd11_stat *)]; struct freebsd11_stat * sb; char sb_r_[PADR_(struct freebsd11_stat *)];
};
struct freebsd11_freebsd64_lstat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct freebsd11_stat *)]; struct freebsd11_stat * ub; char ub_r_[PADR_(struct freebsd11_stat *)];
};
struct freebsd11_freebsd64_getdirentries_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char count_l_[PADL_(u_int)]; u_int count; char count_r_[PADR_(u_int)];
	char basep_l_[PADL_(long *)]; long * basep; char basep_r_[PADR_(long *)];
};
struct freebsd11_freebsd64_getdents_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(char *)]; char * buf; char buf_r_[PADR_(char *)];
	char count_l_[PADL_(size_t)]; size_t count; char count_r_[PADR_(size_t)];
};
struct freebsd11_freebsd64_nstat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct nstat *)]; struct nstat * ub; char ub_r_[PADR_(struct nstat *)];
};
struct freebsd11_freebsd64_nfstat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char sb_l_[PADL_(struct nstat *)]; struct nstat * sb; char sb_r_[PADR_(struct nstat *)];
};
struct freebsd11_freebsd64_nlstat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct nstat *)]; struct nstat * ub; char ub_r_[PADR_(struct nstat *)];
};
struct freebsd11_freebsd64_fhstat_args {
	char u_fhp_l_[PADL_(const struct fhandle *)]; const struct fhandle * u_fhp; char u_fhp_r_[PADR_(const struct fhandle *)];
	char sb_l_[PADL_(struct freebsd11_stat *)]; struct freebsd11_stat * sb; char sb_r_[PADR_(struct freebsd11_stat *)];
};
struct freebsd11_freebsd64_kevent_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char changelist_l_[PADL_(struct kevent_freebsd1164 *)]; struct kevent_freebsd1164 * changelist; char changelist_r_[PADR_(struct kevent_freebsd1164 *)];
	char nchanges_l_[PADL_(int)]; int nchanges; char nchanges_r_[PADR_(int)];
	char eventlist_l_[PADL_(struct kevent_freebsd1164 *)]; struct kevent_freebsd1164 * eventlist; char eventlist_r_[PADR_(struct kevent_freebsd1164 *)];
	char nevents_l_[PADL_(int)]; int nevents; char nevents_r_[PADR_(int)];
	char timeout_l_[PADL_(const struct timespec *)]; const struct timespec * timeout; char timeout_r_[PADR_(const struct timespec *)];
};
struct freebsd11_freebsd64_getfsstat_args {
	char buf_l_[PADL_(struct freebsd11_statfs *)]; struct freebsd11_statfs * buf; char buf_r_[PADR_(struct freebsd11_statfs *)];
	char bufsize_l_[PADL_(long)]; long bufsize; char bufsize_r_[PADR_(long)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};
struct freebsd11_freebsd64_statfs_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char buf_l_[PADL_(struct freebsd11_statfs *)]; struct freebsd11_statfs * buf; char buf_r_[PADR_(struct freebsd11_statfs *)];
};
struct freebsd11_freebsd64_fstatfs_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(struct freebsd11_statfs *)]; struct freebsd11_statfs * buf; char buf_r_[PADR_(struct freebsd11_statfs *)];
};
struct freebsd11_freebsd64_fhstatfs_args {
	char u_fhp_l_[PADL_(const struct fhandle *)]; const struct fhandle * u_fhp; char u_fhp_r_[PADR_(const struct fhandle *)];
	char buf_l_[PADL_(struct freebsd11_statfs *)]; struct freebsd11_statfs * buf; char buf_r_[PADR_(struct freebsd11_statfs *)];
};
struct freebsd11_freebsd64_fstatat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char buf_l_[PADL_(struct freebsd11_stat *)]; struct freebsd11_stat * buf; char buf_r_[PADR_(struct freebsd11_stat *)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct freebsd11_freebsd64_mknodat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char dev_l_[PADL_(uint32_t)]; uint32_t dev; char dev_r_[PADR_(uint32_t)];
};
int	freebsd11_freebsd64_mknod(struct thread *, struct freebsd11_freebsd64_mknod_args *);
int	freebsd11_freebsd64_stat(struct thread *, struct freebsd11_freebsd64_stat_args *);
int	freebsd11_freebsd64_fstat(struct thread *, struct freebsd11_freebsd64_fstat_args *);
int	freebsd11_freebsd64_lstat(struct thread *, struct freebsd11_freebsd64_lstat_args *);
int	freebsd11_freebsd64_getdirentries(struct thread *, struct freebsd11_freebsd64_getdirentries_args *);
int	freebsd11_freebsd64_getdents(struct thread *, struct freebsd11_freebsd64_getdents_args *);
int	freebsd11_freebsd64_nstat(struct thread *, struct freebsd11_freebsd64_nstat_args *);
int	freebsd11_freebsd64_nfstat(struct thread *, struct freebsd11_freebsd64_nfstat_args *);
int	freebsd11_freebsd64_nlstat(struct thread *, struct freebsd11_freebsd64_nlstat_args *);
int	freebsd11_freebsd64_fhstat(struct thread *, struct freebsd11_freebsd64_fhstat_args *);
int	freebsd11_freebsd64_kevent(struct thread *, struct freebsd11_freebsd64_kevent_args *);
int	freebsd11_freebsd64_getfsstat(struct thread *, struct freebsd11_freebsd64_getfsstat_args *);
int	freebsd11_freebsd64_statfs(struct thread *, struct freebsd11_freebsd64_statfs_args *);
int	freebsd11_freebsd64_fstatfs(struct thread *, struct freebsd11_freebsd64_fstatfs_args *);
int	freebsd11_freebsd64_fhstatfs(struct thread *, struct freebsd11_freebsd64_fhstatfs_args *);
int	freebsd11_freebsd64_fstatat(struct thread *, struct freebsd11_freebsd64_fstatat_args *);
int	freebsd11_freebsd64_mknodat(struct thread *, struct freebsd11_freebsd64_mknodat_args *);

#endif /* COMPAT_FREEBSD11 */


#ifdef COMPAT_FREEBSD12

struct freebsd12_freebsd64_shm_open_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
int	freebsd12_freebsd64_shm_open(struct thread *, struct freebsd12_freebsd64_shm_open_args *);

#endif /* COMPAT_FREEBSD12 */

#define	FREEBSD64_SYS_AUE_freebsd64_read	AUE_READ
#define	FREEBSD64_SYS_AUE_freebsd64_write	AUE_WRITE
#define	FREEBSD64_SYS_AUE_freebsd64_open	AUE_OPEN_RWTC
#define	FREEBSD64_SYS_AUE_freebsd64_wait4	AUE_WAIT4
#define	FREEBSD64_SYS_AUE_freebsd64_link	AUE_LINK
#define	FREEBSD64_SYS_AUE_freebsd64_unlink	AUE_UNLINK
#define	FREEBSD64_SYS_AUE_freebsd64_chdir	AUE_CHDIR
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_mknod	AUE_MKNOD
#define	FREEBSD64_SYS_AUE_freebsd64_chmod	AUE_CHMOD
#define	FREEBSD64_SYS_AUE_freebsd64_chown	AUE_CHOWN
#define	FREEBSD64_SYS_AUE_freebsd64_break	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_mount	AUE_MOUNT
#define	FREEBSD64_SYS_AUE_freebsd64_unmount	AUE_UMOUNT
#define	FREEBSD64_SYS_AUE_freebsd64_ptrace	AUE_PTRACE
#define	FREEBSD64_SYS_AUE_freebsd64_recvmsg	AUE_RECVMSG
#define	FREEBSD64_SYS_AUE_freebsd64_sendmsg	AUE_SENDMSG
#define	FREEBSD64_SYS_AUE_freebsd64_recvfrom	AUE_RECVFROM
#define	FREEBSD64_SYS_AUE_freebsd64_accept	AUE_ACCEPT
#define	FREEBSD64_SYS_AUE_freebsd64_getpeername	AUE_GETPEERNAME
#define	FREEBSD64_SYS_AUE_freebsd64_getsockname	AUE_GETSOCKNAME
#define	FREEBSD64_SYS_AUE_freebsd64_access	AUE_ACCESS
#define	FREEBSD64_SYS_AUE_freebsd64_chflags	AUE_CHFLAGS
#define	FREEBSD64_SYS_AUE_freebsd64_profil	AUE_PROFILE
#define	FREEBSD64_SYS_AUE_freebsd64_ktrace	AUE_KTRACE
#define	FREEBSD64_SYS_AUE_freebsd64_getlogin	AUE_GETLOGIN
#define	FREEBSD64_SYS_AUE_freebsd64_setlogin	AUE_SETLOGIN
#define	FREEBSD64_SYS_AUE_freebsd64_acct	AUE_ACCT
#define	FREEBSD64_SYS_AUE_freebsd64_sigaltstack	AUE_SIGALTSTACK
#define	FREEBSD64_SYS_AUE_freebsd64_ioctl	AUE_IOCTL
#define	FREEBSD64_SYS_AUE_freebsd64_revoke	AUE_REVOKE
#define	FREEBSD64_SYS_AUE_freebsd64_symlink	AUE_SYMLINK
#define	FREEBSD64_SYS_AUE_freebsd64_readlink	AUE_READLINK
#define	FREEBSD64_SYS_AUE_freebsd64_execve	AUE_EXECVE
#define	FREEBSD64_SYS_AUE_freebsd64_chroot	AUE_CHROOT
#define	FREEBSD64_SYS_AUE_freebsd64_msync	AUE_MSYNC
#define	FREEBSD64_SYS_AUE_freebsd64_munmap	AUE_MUNMAP
#define	FREEBSD64_SYS_AUE_freebsd64_mprotect	AUE_MPROTECT
#define	FREEBSD64_SYS_AUE_freebsd64_madvise	AUE_MADVISE
#define	FREEBSD64_SYS_AUE_freebsd64_mincore	AUE_MINCORE
#define	FREEBSD64_SYS_AUE_freebsd64_getgroups	AUE_GETGROUPS
#define	FREEBSD64_SYS_AUE_freebsd64_setgroups	AUE_SETGROUPS
#define	FREEBSD64_SYS_AUE_freebsd64_setitimer	AUE_SETITIMER
#define	FREEBSD64_SYS_AUE_freebsd64_swapon	AUE_SWAPON
#define	FREEBSD64_SYS_AUE_freebsd64_getitimer	AUE_GETITIMER
#define	FREEBSD64_SYS_AUE_freebsd64_fcntl	AUE_FCNTL
#define	FREEBSD64_SYS_AUE_freebsd64_select	AUE_SELECT
#define	FREEBSD64_SYS_AUE_freebsd64_connect	AUE_CONNECT
#define	FREEBSD64_SYS_AUE_freebsd64_bind	AUE_BIND
#define	FREEBSD64_SYS_AUE_freebsd64_setsockopt	AUE_SETSOCKOPT
#define	FREEBSD64_SYS_AUE_freebsd64_gettimeofday	AUE_GETTIMEOFDAY
#define	FREEBSD64_SYS_AUE_freebsd64_getrusage	AUE_GETRUSAGE
#define	FREEBSD64_SYS_AUE_freebsd64_getsockopt	AUE_GETSOCKOPT
#define	FREEBSD64_SYS_AUE_freebsd64_readv	AUE_READV
#define	FREEBSD64_SYS_AUE_freebsd64_writev	AUE_WRITEV
#define	FREEBSD64_SYS_AUE_freebsd64_settimeofday	AUE_SETTIMEOFDAY
#define	FREEBSD64_SYS_AUE_freebsd64_rename	AUE_RENAME
#define	FREEBSD64_SYS_AUE_freebsd64_mkfifo	AUE_MKFIFO
#define	FREEBSD64_SYS_AUE_freebsd64_sendto	AUE_SENDTO
#define	FREEBSD64_SYS_AUE_freebsd64_socketpair	AUE_SOCKETPAIR
#define	FREEBSD64_SYS_AUE_freebsd64_mkdir	AUE_MKDIR
#define	FREEBSD64_SYS_AUE_freebsd64_rmdir	AUE_RMDIR
#define	FREEBSD64_SYS_AUE_freebsd64_utimes	AUE_UTIMES
#define	FREEBSD64_SYS_AUE_freebsd64_adjtime	AUE_ADJTIME
#define	FREEBSD64_SYS_AUE_freebsd64_quotactl	AUE_QUOTACTL
#define	FREEBSD64_SYS_AUE_freebsd64_nlm_syscall	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_nfssvc	AUE_NFS_SVC
#define	FREEBSD64_SYS_AUE_freebsd64_lgetfh	AUE_LGETFH
#define	FREEBSD64_SYS_AUE_freebsd64_getfh	AUE_NFS_GETFH
#define	FREEBSD64_SYS_AUE_freebsd64_sysarch	AUE_SYSARCH
#define	FREEBSD64_SYS_AUE_freebsd64_rtprio	AUE_RTPRIO
#define	FREEBSD64_SYS_AUE_freebsd64_semsys	AUE_SEMSYS
#define	FREEBSD64_SYS_AUE_freebsd64_msgsys	AUE_MSGSYS
#define	FREEBSD64_SYS_AUE_freebsd64_shmsys	AUE_SHMSYS
#define	FREEBSD64_SYS_AUE_freebsd6_freebsd64_pread	AUE_PREAD
#define	FREEBSD64_SYS_AUE_freebsd6_freebsd64_pwrite	AUE_PWRITE
#define	FREEBSD64_SYS_AUE_freebsd64_ntp_adjtime	AUE_NTP_ADJTIME
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_stat	AUE_STAT
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_fstat	AUE_FSTAT
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_lstat	AUE_LSTAT
#define	FREEBSD64_SYS_AUE_freebsd64_pathconf	AUE_PATHCONF
#define	FREEBSD64_SYS_AUE_getrlimit	AUE_GETRLIMIT
#define	FREEBSD64_SYS_AUE_setrlimit	AUE_SETRLIMIT
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_getdirentries	AUE_GETDIRENTRIES
#define	FREEBSD64_SYS_AUE_freebsd6_freebsd64_mmap	AUE_MMAP
#define	FREEBSD64_SYS_AUE_freebsd6_freebsd64_truncate	AUE_TRUNCATE
#define	FREEBSD64_SYS_AUE_freebsd64___sysctl	AUE_SYSCTL
#define	FREEBSD64_SYS_AUE_freebsd64_mlock	AUE_MLOCK
#define	FREEBSD64_SYS_AUE_freebsd64_munlock	AUE_MUNLOCK
#define	FREEBSD64_SYS_AUE_freebsd64_undelete	AUE_UNDELETE
#define	FREEBSD64_SYS_AUE_freebsd64_futimes	AUE_FUTIMES
#define	FREEBSD64_SYS_AUE_freebsd64_poll	AUE_POLL
#define	FREEBSD64_SYS_AUE_freebsd7_freebsd64___semctl	AUE_SEMCTL
#define	FREEBSD64_SYS_AUE_freebsd64_semop	AUE_SEMOP
#define	FREEBSD64_SYS_AUE_freebsd7_freebsd64_msgctl	AUE_MSGCTL
#define	FREEBSD64_SYS_AUE_freebsd64_msgsnd	AUE_MSGSND
#define	FREEBSD64_SYS_AUE_freebsd64_msgrcv	AUE_MSGRCV
#define	FREEBSD64_SYS_AUE_freebsd64_shmat	AUE_SHMAT
#define	FREEBSD64_SYS_AUE_freebsd7_freebsd64_shmctl	AUE_SHMCTL
#define	FREEBSD64_SYS_AUE_freebsd64_shmdt	AUE_SHMDT
#define	FREEBSD64_SYS_AUE_freebsd64_clock_gettime	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_clock_settime	AUE_CLOCK_SETTIME
#define	FREEBSD64_SYS_AUE_freebsd64_clock_getres	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_ktimer_create	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_ktimer_settime	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_ktimer_gettime	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_nanosleep	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_ffclock_getcounter	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_ffclock_setestimate	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_ffclock_getestimate	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_clock_nanosleep	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_clock_getcpuclockid2	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_ntp_gettime	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_minherit	AUE_MINHERIT
#define	FREEBSD64_SYS_AUE_freebsd64_lchown	AUE_LCHOWN
#define	FREEBSD64_SYS_AUE_freebsd64_aio_read	AUE_AIO_READ
#define	FREEBSD64_SYS_AUE_freebsd64_aio_write	AUE_AIO_WRITE
#define	FREEBSD64_SYS_AUE_freebsd64_lio_listio	AUE_LIO_LISTIO
#define	FREEBSD64_SYS_AUE_freebsd64_kbounce	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_getdents	AUE_O_GETDENTS
#define	FREEBSD64_SYS_AUE_freebsd64_lchmod	AUE_LCHMOD
#define	FREEBSD64_SYS_AUE_freebsd64_lutimes	AUE_LUTIMES
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_nstat	AUE_STAT
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_nfstat	AUE_FSTAT
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_nlstat	AUE_LSTAT
#define	FREEBSD64_SYS_AUE_freebsd64_preadv	AUE_PREADV
#define	FREEBSD64_SYS_AUE_freebsd64_pwritev	AUE_PWRITEV
#define	FREEBSD64_SYS_AUE_freebsd64_fhopen	AUE_FHOPEN
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_fhstat	AUE_FHSTAT
#define	FREEBSD64_SYS_AUE_freebsd64_modstat	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_modfind	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_kldload	AUE_MODLOAD
#define	FREEBSD64_SYS_AUE_freebsd64_kldfind	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_kldstat	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_aio_return	AUE_AIO_RETURN
#define	FREEBSD64_SYS_AUE_freebsd64_aio_suspend	AUE_AIO_SUSPEND
#define	FREEBSD64_SYS_AUE_freebsd64_aio_cancel	AUE_AIO_CANCEL
#define	FREEBSD64_SYS_AUE_freebsd64_aio_error	AUE_AIO_ERROR
#define	FREEBSD64_SYS_AUE_freebsd6_freebsd64_aio_read	AUE_AIO_READ
#define	FREEBSD64_SYS_AUE_freebsd6_freebsd64_aio_write	AUE_AIO_WRITE
#define	FREEBSD64_SYS_AUE_freebsd6_freebsd64_lio_listio	AUE_LIO_LISTIO
#define	FREEBSD64_SYS_AUE_freebsd64___getcwd	AUE_GETCWD
#define	FREEBSD64_SYS_AUE_freebsd64_sched_setparam	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_sched_getparam	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_sched_setscheduler	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_sched_rr_get_interval	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_utrace	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_kldsym	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_jail	AUE_JAIL
#define	FREEBSD64_SYS_AUE_freebsd64_nnpfs_syscall	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_sigprocmask	AUE_SIGPROCMASK
#define	FREEBSD64_SYS_AUE_freebsd64_sigsuspend	AUE_SIGSUSPEND
#define	FREEBSD64_SYS_AUE_freebsd64_sigpending	AUE_SIGPENDING
#define	FREEBSD64_SYS_AUE_freebsd64_sigtimedwait	AUE_SIGWAIT
#define	FREEBSD64_SYS_AUE_freebsd64_sigwaitinfo	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___acl_get_file	AUE_ACL_GET_FILE
#define	FREEBSD64_SYS_AUE_freebsd64___acl_set_file	AUE_ACL_SET_FILE
#define	FREEBSD64_SYS_AUE_freebsd64___acl_get_fd	AUE_ACL_GET_FD
#define	FREEBSD64_SYS_AUE_freebsd64___acl_set_fd	AUE_ACL_SET_FD
#define	FREEBSD64_SYS_AUE_freebsd64___acl_delete_file	AUE_ACL_DELETE_FILE
#define	FREEBSD64_SYS_AUE_freebsd64___acl_aclcheck_file	AUE_ACL_CHECK_FILE
#define	FREEBSD64_SYS_AUE_freebsd64___acl_aclcheck_fd	AUE_ACL_CHECK_FD
#define	FREEBSD64_SYS_AUE_freebsd64_extattrctl	AUE_EXTATTRCTL
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_set_file	AUE_EXTATTR_SET_FILE
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_get_file	AUE_EXTATTR_GET_FILE
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_delete_file	AUE_EXTATTR_DELETE_FILE
#define	FREEBSD64_SYS_AUE_freebsd64_aio_waitcomplete	AUE_AIO_WAITCOMPLETE
#define	FREEBSD64_SYS_AUE_freebsd64_getresuid	AUE_GETRESUID
#define	FREEBSD64_SYS_AUE_freebsd64_getresgid	AUE_GETRESGID
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_kevent	AUE_KEVENT
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_set_fd	AUE_EXTATTR_SET_FD
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_get_fd	AUE_EXTATTR_GET_FD
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_delete_fd	AUE_EXTATTR_DELETE_FD
#define	FREEBSD64_SYS_AUE_freebsd64_eaccess	AUE_EACCESS
#define	FREEBSD64_SYS_AUE_freebsd64_nmount	AUE_NMOUNT
#define	FREEBSD64_SYS_AUE_freebsd64___mac_get_proc	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___mac_set_proc	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___mac_get_fd	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___mac_get_file	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___mac_set_fd	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___mac_set_file	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_kenv	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_lchflags	AUE_LCHFLAGS
#define	FREEBSD64_SYS_AUE_freebsd64_uuidgen	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_sendfile	AUE_SENDFILE
#define	FREEBSD64_SYS_AUE_freebsd64_mac_syscall	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_getfsstat	AUE_GETFSSTAT
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_statfs	AUE_STATFS
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_fstatfs	AUE_FSTATFS
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_fhstatfs	AUE_FHSTATFS
#define	FREEBSD64_SYS_AUE_freebsd64_ksem_init	AUE_SEMINIT
#define	FREEBSD64_SYS_AUE_freebsd64_ksem_open	AUE_SEMOPEN
#define	FREEBSD64_SYS_AUE_freebsd64_ksem_unlink	AUE_SEMUNLINK
#define	FREEBSD64_SYS_AUE_freebsd64_ksem_getvalue	AUE_SEMGETVALUE
#define	FREEBSD64_SYS_AUE_freebsd64___mac_get_pid	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___mac_get_link	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___mac_set_link	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_set_link	AUE_EXTATTR_SET_LINK
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_get_link	AUE_EXTATTR_GET_LINK
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_delete_link	AUE_EXTATTR_DELETE_LINK
#define	FREEBSD64_SYS_AUE_freebsd64___mac_execve	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_sigaction	AUE_SIGACTION
#define	FREEBSD64_SYS_AUE_freebsd64_sigreturn	AUE_SIGRETURN
#define	FREEBSD64_SYS_AUE_freebsd64_getcontext	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_setcontext	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_swapcontext	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_swapoff	AUE_SWAPOFF
#define	FREEBSD64_SYS_AUE_freebsd64___acl_get_link	AUE_ACL_GET_LINK
#define	FREEBSD64_SYS_AUE_freebsd64___acl_set_link	AUE_ACL_SET_LINK
#define	FREEBSD64_SYS_AUE_freebsd64___acl_delete_link	AUE_ACL_DELETE_LINK
#define	FREEBSD64_SYS_AUE_freebsd64___acl_aclcheck_link	AUE_ACL_CHECK_LINK
#define	FREEBSD64_SYS_AUE_freebsd64_sigwait	AUE_SIGWAIT
#define	FREEBSD64_SYS_AUE_freebsd64_thr_create	AUE_THR_CREATE
#define	FREEBSD64_SYS_AUE_freebsd64_thr_exit	AUE_THR_EXIT
#define	FREEBSD64_SYS_AUE_freebsd64_thr_self	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_list_fd	AUE_EXTATTR_LIST_FD
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_list_file	AUE_EXTATTR_LIST_FILE
#define	FREEBSD64_SYS_AUE_freebsd64_extattr_list_link	AUE_EXTATTR_LIST_LINK
#define	FREEBSD64_SYS_AUE_freebsd64_ksem_timedwait	AUE_SEMWAIT
#define	FREEBSD64_SYS_AUE_freebsd64_thr_suspend	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_audit	AUE_AUDIT
#define	FREEBSD64_SYS_AUE_freebsd64_auditon	AUE_AUDITON
#define	FREEBSD64_SYS_AUE_freebsd64_getauid	AUE_GETAUID
#define	FREEBSD64_SYS_AUE_freebsd64_setauid	AUE_SETAUID
#define	FREEBSD64_SYS_AUE_freebsd64_getaudit	AUE_GETAUDIT
#define	FREEBSD64_SYS_AUE_freebsd64_setaudit	AUE_SETAUDIT
#define	FREEBSD64_SYS_AUE_freebsd64_getaudit_addr	AUE_GETAUDIT_ADDR
#define	FREEBSD64_SYS_AUE_freebsd64_setaudit_addr	AUE_SETAUDIT_ADDR
#define	FREEBSD64_SYS_AUE_freebsd64_auditctl	AUE_AUDITCTL
#define	FREEBSD64_SYS_AUE_freebsd64__umtx_op	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_thr_new	AUE_THR_NEW
#define	FREEBSD64_SYS_AUE_freebsd64_sigqueue	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_kmq_open	AUE_MQ_OPEN
#define	FREEBSD64_SYS_AUE_freebsd64_kmq_setattr	AUE_MQ_SETATTR
#define	FREEBSD64_SYS_AUE_freebsd64_kmq_timedreceive	AUE_MQ_TIMEDRECEIVE
#define	FREEBSD64_SYS_AUE_freebsd64_kmq_timedsend	AUE_MQ_TIMEDSEND
#define	FREEBSD64_SYS_AUE_freebsd64_kmq_notify	AUE_MQ_NOTIFY
#define	FREEBSD64_SYS_AUE_freebsd64_kmq_unlink	AUE_MQ_UNLINK
#define	FREEBSD64_SYS_AUE_freebsd64_abort2	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_thr_set_name	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_aio_fsync	AUE_AIO_FSYNC
#define	FREEBSD64_SYS_AUE_freebsd64_rtprio_thread	AUE_RTPRIO
#define	FREEBSD64_SYS_AUE_freebsd64_sctp_generic_sendmsg	AUE_SCTP_GENERIC_SENDMSG
#define	FREEBSD64_SYS_AUE_freebsd64_sctp_generic_sendmsg_iov	AUE_SCTP_GENERIC_SENDMSG_IOV
#define	FREEBSD64_SYS_AUE_freebsd64_sctp_generic_recvmsg	AUE_SCTP_GENERIC_RECVMSG
#define	FREEBSD64_SYS_AUE_freebsd64_pread	AUE_PREAD
#define	FREEBSD64_SYS_AUE_freebsd64_pwrite	AUE_PWRITE
#define	FREEBSD64_SYS_AUE_freebsd64_mmap	AUE_MMAP
#define	FREEBSD64_SYS_AUE_freebsd64_truncate	AUE_TRUNCATE
#define	FREEBSD64_SYS_AUE_freebsd12_freebsd64_shm_open	AUE_SHMOPEN
#define	FREEBSD64_SYS_AUE_freebsd64_shm_unlink	AUE_SHMUNLINK
#define	FREEBSD64_SYS_AUE_freebsd64_cpuset	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_cpuset_getid	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_cpuset_getaffinity	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_cpuset_setaffinity	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_faccessat	AUE_FACCESSAT
#define	FREEBSD64_SYS_AUE_freebsd64_fchmodat	AUE_FCHMODAT
#define	FREEBSD64_SYS_AUE_freebsd64_fchownat	AUE_FCHOWNAT
#define	FREEBSD64_SYS_AUE_freebsd64_fexecve	AUE_FEXECVE
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_fstatat	AUE_FSTATAT
#define	FREEBSD64_SYS_AUE_freebsd64_futimesat	AUE_FUTIMESAT
#define	FREEBSD64_SYS_AUE_freebsd64_linkat	AUE_LINKAT
#define	FREEBSD64_SYS_AUE_freebsd64_mkdirat	AUE_MKDIRAT
#define	FREEBSD64_SYS_AUE_freebsd64_mkfifoat	AUE_MKFIFOAT
#define	FREEBSD64_SYS_AUE_freebsd11_freebsd64_mknodat	AUE_MKNODAT
#define	FREEBSD64_SYS_AUE_freebsd64_openat	AUE_OPENAT_RWTC
#define	FREEBSD64_SYS_AUE_freebsd64_readlinkat	AUE_READLINKAT
#define	FREEBSD64_SYS_AUE_freebsd64_renameat	AUE_RENAMEAT
#define	FREEBSD64_SYS_AUE_freebsd64_symlinkat	AUE_SYMLINKAT
#define	FREEBSD64_SYS_AUE_freebsd64_unlinkat	AUE_UNLINKAT
#define	FREEBSD64_SYS_AUE_freebsd64_gssd_syscall	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_jail_get	AUE_JAIL_GET
#define	FREEBSD64_SYS_AUE_freebsd64_jail_set	AUE_JAIL_SET
#define	FREEBSD64_SYS_AUE_freebsd64___semctl	AUE_SEMCTL
#define	FREEBSD64_SYS_AUE_freebsd64_msgctl	AUE_MSGCTL
#define	FREEBSD64_SYS_AUE_freebsd64_shmctl	AUE_SHMCTL
#define	FREEBSD64_SYS_AUE_freebsd64_lpathconf	AUE_LPATHCONF
#define	FREEBSD64_SYS_AUE_freebsd64___cap_rights_get	AUE_CAP_RIGHTS_GET
#define	FREEBSD64_SYS_AUE_freebsd64_cap_getmode	AUE_CAP_GETMODE
#define	FREEBSD64_SYS_AUE_freebsd64_pdfork	AUE_PDFORK
#define	FREEBSD64_SYS_AUE_freebsd64_pdgetpid	AUE_PDGETPID
#define	FREEBSD64_SYS_AUE_freebsd64_pselect	AUE_SELECT
#define	FREEBSD64_SYS_AUE_freebsd64_getloginclass	AUE_GETLOGINCLASS
#define	FREEBSD64_SYS_AUE_freebsd64_setloginclass	AUE_SETLOGINCLASS
#define	FREEBSD64_SYS_AUE_freebsd64_rctl_get_racct	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_rctl_get_rules	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_rctl_get_limits	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_rctl_add_rule	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_rctl_remove_rule	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_wait6	AUE_WAIT6
#define	FREEBSD64_SYS_AUE_freebsd64_cap_rights_limit	AUE_CAP_RIGHTS_LIMIT
#define	FREEBSD64_SYS_AUE_freebsd64_cap_ioctls_limit	AUE_CAP_IOCTLS_LIMIT
#define	FREEBSD64_SYS_AUE_freebsd64_cap_ioctls_get	AUE_CAP_IOCTLS_GET
#define	FREEBSD64_SYS_AUE_freebsd64_cap_fcntls_get	AUE_CAP_FCNTLS_GET
#define	FREEBSD64_SYS_AUE_freebsd64_bindat	AUE_BINDAT
#define	FREEBSD64_SYS_AUE_freebsd64_connectat	AUE_CONNECTAT
#define	FREEBSD64_SYS_AUE_freebsd64_chflagsat	AUE_CHFLAGSAT
#define	FREEBSD64_SYS_AUE_freebsd64_accept4	AUE_ACCEPT
#define	FREEBSD64_SYS_AUE_freebsd64_pipe2	AUE_PIPE
#define	FREEBSD64_SYS_AUE_freebsd64_aio_mlock	AUE_AIO_MLOCK
#define	FREEBSD64_SYS_AUE_freebsd64_procctl	AUE_PROCCTL
#define	FREEBSD64_SYS_AUE_freebsd64_ppoll	AUE_POLL
#define	FREEBSD64_SYS_AUE_freebsd64_futimens	AUE_FUTIMES
#define	FREEBSD64_SYS_AUE_freebsd64_utimensat	AUE_FUTIMESAT
#define	FREEBSD64_SYS_AUE_freebsd64_fstat	AUE_FSTAT
#define	FREEBSD64_SYS_AUE_freebsd64_fstatat	AUE_FSTATAT
#define	FREEBSD64_SYS_AUE_freebsd64_fhstat	AUE_FHSTAT
#define	FREEBSD64_SYS_AUE_freebsd64_getdirentries	AUE_GETDIRENTRIES
#define	FREEBSD64_SYS_AUE_freebsd64_statfs	AUE_STATFS
#define	FREEBSD64_SYS_AUE_freebsd64_fstatfs	AUE_FSTATFS
#define	FREEBSD64_SYS_AUE_freebsd64_getfsstat	AUE_GETFSSTAT
#define	FREEBSD64_SYS_AUE_freebsd64_fhstatfs	AUE_FHSTATFS
#define	FREEBSD64_SYS_AUE_freebsd64_mknodat	AUE_MKNODAT
#define	FREEBSD64_SYS_AUE_freebsd64_kevent	AUE_KEVENT
#define	FREEBSD64_SYS_AUE_freebsd64_cpuset_getdomain	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_cpuset_setdomain	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_getrandom	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_getfhat	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_fhlink	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_fhlinkat	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_fhreadlink	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64_funlinkat	AUE_UNLINKAT
#define	FREEBSD64_SYS_AUE_freebsd64_copy_file_range	AUE_NULL
#define	FREEBSD64_SYS_AUE_freebsd64___sysctlbyname	AUE_SYSCTL
#define	FREEBSD64_SYS_AUE_freebsd64_shm_open2	AUE_SHMOPEN
#define	FREEBSD64_SYS_AUE_freebsd64_shm_rename	AUE_SHMRENAME

#undef PAD_
#undef PADL_
#undef PADR_

#endif /* !_FREEBSD64_PROTO_H_ */
