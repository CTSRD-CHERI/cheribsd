/*
 * System call prototypes.
 *
 * DO NOT EDIT-- this file is automatically @generated.
 * $FreeBSD$
 */

#ifndef _CHERIABI_PROTO_H_
#define	_CHERIABI_PROTO_H_

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

struct cheriabi_read_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(void * __capability)]; void * __capability buf; char buf_r_[PADR_(void * __capability)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
};
struct cheriabi_write_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(const void * __capability)]; const void * __capability buf; char buf_r_[PADR_(const void * __capability)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
};
struct cheriabi_open_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct cheriabi_wait4_args {
	char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
	char status_l_[PADL_(int * __capability)]; int * __capability status; char status_r_[PADR_(int * __capability)];
	char options_l_[PADL_(int)]; int options; char options_r_[PADR_(int)];
	char rusage_l_[PADL_(struct rusage * __capability)]; struct rusage * __capability rusage; char rusage_r_[PADR_(struct rusage * __capability)];
};
struct cheriabi_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char to_l_[PADL_(const char * __capability)]; const char * __capability to; char to_r_[PADR_(const char * __capability)];
};
struct cheriabi_unlink_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_chdir_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_chmod_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct cheriabi_chown_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char uid_l_[PADL_(int)]; int uid; char uid_r_[PADR_(int)];
	char gid_l_[PADL_(int)]; int gid; char gid_r_[PADR_(int)];
};
struct cheriabi_mount_args {
	char type_l_[PADL_(const char * __capability)]; const char * __capability type; char type_r_[PADR_(const char * __capability)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
};
struct cheriabi_unmount_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_ptrace_args {
	char req_l_[PADL_(int)]; int req; char req_r_[PADR_(int)];
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char addr_l_[PADL_(char * __capability)]; char * __capability addr; char addr_r_[PADR_(char * __capability)];
	char data_l_[PADL_(int)]; int data; char data_r_[PADR_(int)];
};
struct cheriabi_recvmsg_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char msg_l_[PADL_(struct msghdr_c * __capability)]; struct msghdr_c * __capability msg; char msg_r_[PADR_(struct msghdr_c * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_sendmsg_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char msg_l_[PADL_(const struct msghdr_c * __capability)]; const struct msghdr_c * __capability msg; char msg_r_[PADR_(const struct msghdr_c * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_recvfrom_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char buf_l_[PADL_(void * __capability)]; void * __capability buf; char buf_r_[PADR_(void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char from_l_[PADL_(struct sockaddr * __capability)]; struct sockaddr * __capability from; char from_r_[PADR_(struct sockaddr * __capability)];
	char fromlenaddr_l_[PADL_(__socklen_t * __capability)]; __socklen_t * __capability fromlenaddr; char fromlenaddr_r_[PADR_(__socklen_t * __capability)];
};
struct cheriabi_accept_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(struct sockaddr * __capability)]; struct sockaddr * __capability name; char name_r_[PADR_(struct sockaddr * __capability)];
	char anamelen_l_[PADL_(__socklen_t * __capability)]; __socklen_t * __capability anamelen; char anamelen_r_[PADR_(__socklen_t * __capability)];
};
struct cheriabi_getpeername_args {
	char fdes_l_[PADL_(int)]; int fdes; char fdes_r_[PADR_(int)];
	char asa_l_[PADL_(struct sockaddr * __capability)]; struct sockaddr * __capability asa; char asa_r_[PADR_(struct sockaddr * __capability)];
	char alen_l_[PADL_(__socklen_t * __capability)]; __socklen_t * __capability alen; char alen_r_[PADR_(__socklen_t * __capability)];
};
struct cheriabi_getsockname_args {
	char fdes_l_[PADL_(int)]; int fdes; char fdes_r_[PADR_(int)];
	char asa_l_[PADL_(struct sockaddr * __capability)]; struct sockaddr * __capability asa; char asa_r_[PADR_(struct sockaddr * __capability)];
	char alen_l_[PADL_(__socklen_t * __capability)]; __socklen_t * __capability alen; char alen_r_[PADR_(__socklen_t * __capability)];
};
struct cheriabi_access_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char amode_l_[PADL_(int)]; int amode; char amode_r_[PADR_(int)];
};
struct cheriabi_chflags_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(u_long)]; u_long flags; char flags_r_[PADR_(u_long)];
};
struct cheriabi_profil_args {
	char samples_l_[PADL_(char * __capability)]; char * __capability samples; char samples_r_[PADR_(char * __capability)];
	char size_l_[PADL_(size_t)]; size_t size; char size_r_[PADR_(size_t)];
	char offset_l_[PADL_(size_t)]; size_t offset; char offset_r_[PADR_(size_t)];
	char scale_l_[PADL_(u_int)]; u_int scale; char scale_r_[PADR_(u_int)];
};
struct cheriabi_ktrace_args {
	char fname_l_[PADL_(const char * __capability)]; const char * __capability fname; char fname_r_[PADR_(const char * __capability)];
	char ops_l_[PADL_(int)]; int ops; char ops_r_[PADR_(int)];
	char facs_l_[PADL_(int)]; int facs; char facs_r_[PADR_(int)];
	char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
};
struct cheriabi_getlogin_args {
	char namebuf_l_[PADL_(char * __capability)]; char * __capability namebuf; char namebuf_r_[PADR_(char * __capability)];
	char namelen_l_[PADL_(u_int)]; u_int namelen; char namelen_r_[PADR_(u_int)];
};
struct cheriabi_setlogin_args {
	char namebuf_l_[PADL_(const char * __capability)]; const char * __capability namebuf; char namebuf_r_[PADR_(const char * __capability)];
};
struct cheriabi_acct_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_sigaltstack_args {
	char ss_l_[PADL_(const struct sigaltstack_c * __capability)]; const struct sigaltstack_c * __capability ss; char ss_r_[PADR_(const struct sigaltstack_c * __capability)];
	char oss_l_[PADL_(struct sigaltstack_c * __capability)]; struct sigaltstack_c * __capability oss; char oss_r_[PADR_(struct sigaltstack_c * __capability)];
};
struct cheriabi_ioctl_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char com_l_[PADL_(u_long)]; u_long com; char com_r_[PADR_(u_long)];
	char data_l_[PADL_(char * __capability)]; char * __capability data; char data_r_[PADR_(char * __capability)];
};
struct cheriabi_revoke_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_symlink_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char link_l_[PADL_(const char * __capability)]; const char * __capability link; char link_r_[PADR_(const char * __capability)];
};
struct cheriabi_readlink_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char buf_l_[PADL_(char * __capability)]; char * __capability buf; char buf_r_[PADR_(char * __capability)];
	char count_l_[PADL_(size_t)]; size_t count; char count_r_[PADR_(size_t)];
};
struct cheriabi_execve_args {
	char fname_l_[PADL_(const char * __capability)]; const char * __capability fname; char fname_r_[PADR_(const char * __capability)];
	char argv_l_[PADL_(char * __capability * __capability)]; char * __capability * __capability argv; char argv_r_[PADR_(char * __capability * __capability)];
	char envv_l_[PADL_(char * __capability * __capability)]; char * __capability * __capability envv; char envv_r_[PADR_(char * __capability * __capability)];
};
struct cheriabi_chroot_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_msync_args {
	char addr_l_[PADL_(void * __capability)]; void * __capability addr; char addr_r_[PADR_(void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_munmap_args {
	char addr_l_[PADL_(void * __capability)]; void * __capability addr; char addr_r_[PADR_(void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
};
struct cheriabi_mprotect_args {
	char addr_l_[PADL_(const void * __capability)]; const void * __capability addr; char addr_r_[PADR_(const void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char prot_l_[PADL_(int)]; int prot; char prot_r_[PADR_(int)];
};
struct cheriabi_madvise_args {
	char addr_l_[PADL_(void * __capability)]; void * __capability addr; char addr_r_[PADR_(void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char behav_l_[PADL_(int)]; int behav; char behav_r_[PADR_(int)];
};
struct cheriabi_mincore_args {
	char addr_l_[PADL_(const void * __capability)]; const void * __capability addr; char addr_r_[PADR_(const void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char vec_l_[PADL_(char * __capability)]; char * __capability vec; char vec_r_[PADR_(char * __capability)];
};
struct cheriabi_getgroups_args {
	char gidsetsize_l_[PADL_(u_int)]; u_int gidsetsize; char gidsetsize_r_[PADR_(u_int)];
	char gidset_l_[PADL_(gid_t * __capability)]; gid_t * __capability gidset; char gidset_r_[PADR_(gid_t * __capability)];
};
struct cheriabi_setgroups_args {
	char gidsetsize_l_[PADL_(u_int)]; u_int gidsetsize; char gidsetsize_r_[PADR_(u_int)];
	char gidset_l_[PADL_(const gid_t * __capability)]; const gid_t * __capability gidset; char gidset_r_[PADR_(const gid_t * __capability)];
};
struct cheriabi_setitimer_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char itv_l_[PADL_(const struct itimerval * __capability)]; const struct itimerval * __capability itv; char itv_r_[PADR_(const struct itimerval * __capability)];
	char oitv_l_[PADL_(struct itimerval * __capability)]; struct itimerval * __capability oitv; char oitv_r_[PADR_(struct itimerval * __capability)];
};
struct cheriabi_swapon_args {
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
};
struct cheriabi_getitimer_args {
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char itv_l_[PADL_(struct itimerval * __capability)]; struct itimerval * __capability itv; char itv_r_[PADR_(struct itimerval * __capability)];
};
struct cheriabi_fcntl_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char arg_l_[PADL_(intcap_t)]; intcap_t arg; char arg_r_[PADR_(intcap_t)];
};
struct cheriabi_select_args {
	char nd_l_[PADL_(int)]; int nd; char nd_r_[PADR_(int)];
	char in_l_[PADL_(fd_set * __capability)]; fd_set * __capability in; char in_r_[PADR_(fd_set * __capability)];
	char ou_l_[PADL_(fd_set * __capability)]; fd_set * __capability ou; char ou_r_[PADR_(fd_set * __capability)];
	char ex_l_[PADL_(fd_set * __capability)]; fd_set * __capability ex; char ex_r_[PADR_(fd_set * __capability)];
	char tv_l_[PADL_(struct timeval * __capability)]; struct timeval * __capability tv; char tv_r_[PADR_(struct timeval * __capability)];
};
struct cheriabi_connect_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(const struct sockaddr * __capability)]; const struct sockaddr * __capability name; char name_r_[PADR_(const struct sockaddr * __capability)];
	char namelen_l_[PADL_(__socklen_t)]; __socklen_t namelen; char namelen_r_[PADR_(__socklen_t)];
};
struct cheriabi_bind_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(const struct sockaddr * __capability)]; const struct sockaddr * __capability name; char name_r_[PADR_(const struct sockaddr * __capability)];
	char namelen_l_[PADL_(__socklen_t)]; __socklen_t namelen; char namelen_r_[PADR_(__socklen_t)];
};
struct cheriabi_setsockopt_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char level_l_[PADL_(int)]; int level; char level_r_[PADR_(int)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
	char val_l_[PADL_(const void * __capability)]; const void * __capability val; char val_r_[PADR_(const void * __capability)];
	char valsize_l_[PADL_(__socklen_t)]; __socklen_t valsize; char valsize_r_[PADR_(__socklen_t)];
};
struct cheriabi_gettimeofday_args {
	char tp_l_[PADL_(struct timeval * __capability)]; struct timeval * __capability tp; char tp_r_[PADR_(struct timeval * __capability)];
	char tzp_l_[PADL_(struct timezone * __capability)]; struct timezone * __capability tzp; char tzp_r_[PADR_(struct timezone * __capability)];
};
struct cheriabi_getrusage_args {
	char who_l_[PADL_(int)]; int who; char who_r_[PADR_(int)];
	char rusage_l_[PADL_(struct rusage * __capability)]; struct rusage * __capability rusage; char rusage_r_[PADR_(struct rusage * __capability)];
};
struct cheriabi_getsockopt_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char level_l_[PADL_(int)]; int level; char level_r_[PADR_(int)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
	char val_l_[PADL_(void * __capability)]; void * __capability val; char val_r_[PADR_(void * __capability)];
	char avalsize_l_[PADL_(__socklen_t * __capability)]; __socklen_t * __capability avalsize; char avalsize_r_[PADR_(__socklen_t * __capability)];
};
struct cheriabi_readv_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iovp; char iovp_r_[PADR_(struct iovec_c * __capability)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
};
struct cheriabi_writev_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iovp; char iovp_r_[PADR_(struct iovec_c * __capability)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
};
struct cheriabi_settimeofday_args {
	char tv_l_[PADL_(const struct timeval * __capability)]; const struct timeval * __capability tv; char tv_r_[PADR_(const struct timeval * __capability)];
	char tzp_l_[PADL_(const struct timezone * __capability)]; const struct timezone * __capability tzp; char tzp_r_[PADR_(const struct timezone * __capability)];
};
struct cheriabi_rename_args {
	char from_l_[PADL_(const char * __capability)]; const char * __capability from; char from_r_[PADR_(const char * __capability)];
	char to_l_[PADL_(const char * __capability)]; const char * __capability to; char to_r_[PADR_(const char * __capability)];
};
struct cheriabi_mkfifo_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct cheriabi_sendto_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char buf_l_[PADL_(const void * __capability)]; const void * __capability buf; char buf_r_[PADR_(const void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char to_l_[PADL_(const struct sockaddr * __capability)]; const struct sockaddr * __capability to; char to_r_[PADR_(const struct sockaddr * __capability)];
	char tolen_l_[PADL_(__socklen_t)]; __socklen_t tolen; char tolen_r_[PADR_(__socklen_t)];
};
struct cheriabi_socketpair_args {
	char domain_l_[PADL_(int)]; int domain; char domain_r_[PADR_(int)];
	char type_l_[PADL_(int)]; int type; char type_r_[PADR_(int)];
	char protocol_l_[PADL_(int)]; int protocol; char protocol_r_[PADR_(int)];
	char rsv_l_[PADL_(int * __capability)]; int * __capability rsv; char rsv_r_[PADR_(int * __capability)];
};
struct cheriabi_mkdir_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct cheriabi_rmdir_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_utimes_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char tptr_l_[PADL_(const struct timeval * __capability)]; const struct timeval * __capability tptr; char tptr_r_[PADR_(const struct timeval * __capability)];
};
struct cheriabi_adjtime_args {
	char delta_l_[PADL_(const struct timeval * __capability)]; const struct timeval * __capability delta; char delta_r_[PADR_(const struct timeval * __capability)];
	char olddelta_l_[PADL_(struct timeval * __capability)]; struct timeval * __capability olddelta; char olddelta_r_[PADR_(struct timeval * __capability)];
};
struct cheriabi_quotactl_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char uid_l_[PADL_(int)]; int uid; char uid_r_[PADR_(int)];
	char arg_l_[PADL_(void * __capability)]; void * __capability arg; char arg_r_[PADR_(void * __capability)];
};
struct cheriabi_nlm_syscall_args {
	char debug_level_l_[PADL_(int)]; int debug_level; char debug_level_r_[PADR_(int)];
	char grace_period_l_[PADL_(int)]; int grace_period; char grace_period_r_[PADR_(int)];
	char addr_count_l_[PADL_(int)]; int addr_count; char addr_count_r_[PADR_(int)];
	char addrs_l_[PADL_(char * __capability * __capability)]; char * __capability * __capability addrs; char addrs_r_[PADR_(char * __capability * __capability)];
};
struct cheriabi_nfssvc_args {
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
	char argp_l_[PADL_(void * __capability)]; void * __capability argp; char argp_r_[PADR_(void * __capability)];
};
struct cheriabi_lgetfh_args {
	char fname_l_[PADL_(const char * __capability)]; const char * __capability fname; char fname_r_[PADR_(const char * __capability)];
	char fhp_l_[PADL_(struct fhandle * __capability)]; struct fhandle * __capability fhp; char fhp_r_[PADR_(struct fhandle * __capability)];
};
struct cheriabi_getfh_args {
	char fname_l_[PADL_(const char * __capability)]; const char * __capability fname; char fname_r_[PADR_(const char * __capability)];
	char fhp_l_[PADL_(struct fhandle * __capability)]; struct fhandle * __capability fhp; char fhp_r_[PADR_(struct fhandle * __capability)];
};
struct cheriabi_sysarch_args {
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char parms_l_[PADL_(char * __capability)]; char * __capability parms; char parms_r_[PADR_(char * __capability)];
};
struct cheriabi_rtprio_args {
	char function_l_[PADL_(int)]; int function; char function_r_[PADR_(int)];
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char rtp_l_[PADL_(struct rtprio * __capability)]; struct rtprio * __capability rtp; char rtp_r_[PADR_(struct rtprio * __capability)];
};
struct cheriabi_ntp_adjtime_args {
	char tp_l_[PADL_(struct timex * __capability)]; struct timex * __capability tp; char tp_r_[PADR_(struct timex * __capability)];
};
struct cheriabi_pathconf_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
};
struct cheriabi___getrlimit_args {
	char which_l_[PADL_(u_int)]; u_int which; char which_r_[PADR_(u_int)];
	char rlp_l_[PADL_(struct rlimit * __capability)]; struct rlimit * __capability rlp; char rlp_r_[PADR_(struct rlimit * __capability)];
};
struct cheriabi___setrlimit_args {
	char which_l_[PADL_(u_int)]; u_int which; char which_r_[PADR_(u_int)];
	char rlp_l_[PADL_(struct rlimit * __capability)]; struct rlimit * __capability rlp; char rlp_r_[PADR_(struct rlimit * __capability)];
};
struct cheriabi___sysctl_args {
	char name_l_[PADL_(int * __capability)]; int * __capability name; char name_r_[PADR_(int * __capability)];
	char namelen_l_[PADL_(u_int)]; u_int namelen; char namelen_r_[PADR_(u_int)];
	char old_l_[PADL_(void * __capability)]; void * __capability old; char old_r_[PADR_(void * __capability)];
	char oldlenp_l_[PADL_(size_t * __capability)]; size_t * __capability oldlenp; char oldlenp_r_[PADR_(size_t * __capability)];
	char new_l_[PADL_(const void * __capability)]; const void * __capability new; char new_r_[PADR_(const void * __capability)];
	char newlen_l_[PADL_(size_t)]; size_t newlen; char newlen_r_[PADR_(size_t)];
};
struct cheriabi_mlock_args {
	char addr_l_[PADL_(const void * __capability)]; const void * __capability addr; char addr_r_[PADR_(const void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
};
struct cheriabi_munlock_args {
	char addr_l_[PADL_(const void * __capability)]; const void * __capability addr; char addr_r_[PADR_(const void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
};
struct cheriabi_undelete_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_futimes_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char tptr_l_[PADL_(const struct timeval * __capability)]; const struct timeval * __capability tptr; char tptr_r_[PADR_(const struct timeval * __capability)];
};
struct cheriabi_poll_args {
	char fds_l_[PADL_(struct pollfd * __capability)]; struct pollfd * __capability fds; char fds_r_[PADR_(struct pollfd * __capability)];
	char nfds_l_[PADL_(u_int)]; u_int nfds; char nfds_r_[PADR_(u_int)];
	char timeout_l_[PADL_(int)]; int timeout; char timeout_r_[PADR_(int)];
};
struct cheriabi_semop_args {
	char semid_l_[PADL_(int)]; int semid; char semid_r_[PADR_(int)];
	char sops_l_[PADL_(struct sembuf * __capability)]; struct sembuf * __capability sops; char sops_r_[PADR_(struct sembuf * __capability)];
	char nsops_l_[PADL_(size_t)]; size_t nsops; char nsops_r_[PADR_(size_t)];
};
struct cheriabi_msgsnd_args {
	char msqid_l_[PADL_(int)]; int msqid; char msqid_r_[PADR_(int)];
	char msgp_l_[PADL_(const void * __capability)]; const void * __capability msgp; char msgp_r_[PADR_(const void * __capability)];
	char msgsz_l_[PADL_(size_t)]; size_t msgsz; char msgsz_r_[PADR_(size_t)];
	char msgflg_l_[PADL_(int)]; int msgflg; char msgflg_r_[PADR_(int)];
};
struct cheriabi_msgrcv_args {
	char msqid_l_[PADL_(int)]; int msqid; char msqid_r_[PADR_(int)];
	char msgp_l_[PADL_(void * __capability)]; void * __capability msgp; char msgp_r_[PADR_(void * __capability)];
	char msgsz_l_[PADL_(size_t)]; size_t msgsz; char msgsz_r_[PADR_(size_t)];
	char msgtyp_l_[PADL_(long)]; long msgtyp; char msgtyp_r_[PADR_(long)];
	char msgflg_l_[PADL_(int)]; int msgflg; char msgflg_r_[PADR_(int)];
};
struct cheriabi_shmat_args {
	char shmid_l_[PADL_(int)]; int shmid; char shmid_r_[PADR_(int)];
	char shmaddr_l_[PADL_(const void * __capability)]; const void * __capability shmaddr; char shmaddr_r_[PADR_(const void * __capability)];
	char shmflg_l_[PADL_(int)]; int shmflg; char shmflg_r_[PADR_(int)];
};
struct cheriabi_shmdt_args {
	char shmaddr_l_[PADL_(const void * __capability)]; const void * __capability shmaddr; char shmaddr_r_[PADR_(const void * __capability)];
};
struct cheriabi_clock_gettime_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char tp_l_[PADL_(struct timespec * __capability)]; struct timespec * __capability tp; char tp_r_[PADR_(struct timespec * __capability)];
};
struct cheriabi_clock_settime_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char tp_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability tp; char tp_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_clock_getres_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char tp_l_[PADL_(struct timespec * __capability)]; struct timespec * __capability tp; char tp_r_[PADR_(struct timespec * __capability)];
};
struct cheriabi_ktimer_create_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char evp_l_[PADL_(struct sigevent_c * __capability)]; struct sigevent_c * __capability evp; char evp_r_[PADR_(struct sigevent_c * __capability)];
	char timerid_l_[PADL_(int * __capability)]; int * __capability timerid; char timerid_r_[PADR_(int * __capability)];
};
struct cheriabi_ktimer_settime_args {
	char timerid_l_[PADL_(int)]; int timerid; char timerid_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char value_l_[PADL_(const struct itimerspec * __capability)]; const struct itimerspec * __capability value; char value_r_[PADR_(const struct itimerspec * __capability)];
	char ovalue_l_[PADL_(struct itimerspec * __capability)]; struct itimerspec * __capability ovalue; char ovalue_r_[PADR_(struct itimerspec * __capability)];
};
struct cheriabi_ktimer_gettime_args {
	char timerid_l_[PADL_(int)]; int timerid; char timerid_r_[PADR_(int)];
	char value_l_[PADL_(struct itimerspec * __capability)]; struct itimerspec * __capability value; char value_r_[PADR_(struct itimerspec * __capability)];
};
struct cheriabi_nanosleep_args {
	char rqtp_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability rqtp; char rqtp_r_[PADR_(const struct timespec * __capability)];
	char rmtp_l_[PADL_(struct timespec * __capability)]; struct timespec * __capability rmtp; char rmtp_r_[PADR_(struct timespec * __capability)];
};
struct cheriabi_ffclock_getcounter_args {
	char ffcount_l_[PADL_(ffcounter * __capability)]; ffcounter * __capability ffcount; char ffcount_r_[PADR_(ffcounter * __capability)];
};
struct cheriabi_ffclock_setestimate_args {
	char cest_l_[PADL_(struct ffclock_estimate * __capability)]; struct ffclock_estimate * __capability cest; char cest_r_[PADR_(struct ffclock_estimate * __capability)];
};
struct cheriabi_ffclock_getestimate_args {
	char cest_l_[PADL_(struct ffclock_estimate * __capability)]; struct ffclock_estimate * __capability cest; char cest_r_[PADR_(struct ffclock_estimate * __capability)];
};
struct cheriabi_clock_nanosleep_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char rqtp_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability rqtp; char rqtp_r_[PADR_(const struct timespec * __capability)];
	char rmtp_l_[PADL_(struct timespec * __capability)]; struct timespec * __capability rmtp; char rmtp_r_[PADR_(struct timespec * __capability)];
};
struct cheriabi_clock_getcpuclockid2_args {
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char which_l_[PADL_(int)]; int which; char which_r_[PADR_(int)];
	char clock_id_l_[PADL_(clockid_t * __capability)]; clockid_t * __capability clock_id; char clock_id_r_[PADR_(clockid_t * __capability)];
};
struct cheriabi_ntp_gettime_args {
	char ntvp_l_[PADL_(struct ntptimeval * __capability)]; struct ntptimeval * __capability ntvp; char ntvp_r_[PADR_(struct ntptimeval * __capability)];
};
struct cheriabi_minherit_args {
	char addr_l_[PADL_(void * __capability)]; void * __capability addr; char addr_r_[PADR_(void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char inherit_l_[PADL_(int)]; int inherit; char inherit_r_[PADR_(int)];
};
struct cheriabi_lchown_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char uid_l_[PADL_(int)]; int uid; char uid_r_[PADR_(int)];
	char gid_l_[PADL_(int)]; int gid; char gid_r_[PADR_(int)];
};
struct cheriabi_aio_read_args {
	char aiocbp_l_[PADL_(struct aiocb_c * __capability)]; struct aiocb_c * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability)];
};
struct cheriabi_aio_write_args {
	char aiocbp_l_[PADL_(struct aiocb_c * __capability)]; struct aiocb_c * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability)];
};
struct cheriabi_lio_listio_args {
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
	char acb_list_l_[PADL_(struct aiocb_c * __capability const * __capability)]; struct aiocb_c * __capability const * __capability acb_list; char acb_list_r_[PADR_(struct aiocb_c * __capability const * __capability)];
	char nent_l_[PADL_(int)]; int nent; char nent_r_[PADR_(int)];
	char sig_l_[PADL_(struct sigevent_c * __capability)]; struct sigevent_c * __capability sig; char sig_r_[PADR_(struct sigevent_c * __capability)];
};
struct cheriabi_kbounce_args {
	char src_l_[PADL_(const void * __capability)]; const void * __capability src; char src_r_[PADR_(const void * __capability)];
	char dst_l_[PADL_(void * __capability)]; void * __capability dst; char dst_r_[PADR_(void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_flag_captured_args {
	char message_l_[PADL_(const char * __capability)]; const char * __capability message; char message_r_[PADR_(const char * __capability)];
};
struct cheriabi_lchmod_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct cheriabi_lutimes_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char tptr_l_[PADL_(const struct timeval * __capability)]; const struct timeval * __capability tptr; char tptr_r_[PADR_(const struct timeval * __capability)];
};
struct cheriabi_preadv_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iovp; char iovp_r_[PADR_(struct iovec_c * __capability)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct cheriabi_pwritev_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iovp; char iovp_r_[PADR_(struct iovec_c * __capability)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct cheriabi_fhopen_args {
	char u_fhp_l_[PADL_(const struct fhandle * __capability)]; const struct fhandle * __capability u_fhp; char u_fhp_r_[PADR_(const struct fhandle * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_modstat_args {
	char modid_l_[PADL_(int)]; int modid; char modid_r_[PADR_(int)];
	char stat_l_[PADL_(struct module_stat * __capability)]; struct module_stat * __capability stat; char stat_r_[PADR_(struct module_stat * __capability)];
};
struct cheriabi_modfind_args {
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
};
struct cheriabi_kldload_args {
	char file_l_[PADL_(const char * __capability)]; const char * __capability file; char file_r_[PADR_(const char * __capability)];
};
struct cheriabi_kldfind_args {
	char file_l_[PADL_(const char * __capability)]; const char * __capability file; char file_r_[PADR_(const char * __capability)];
};
struct cheriabi_kldstat_args {
	char fileid_l_[PADL_(int)]; int fileid; char fileid_r_[PADR_(int)];
	char stat_l_[PADL_(struct kld_file_stat_c * __capability)]; struct kld_file_stat_c * __capability stat; char stat_r_[PADR_(struct kld_file_stat_c * __capability)];
};
struct cheriabi_aio_return_args {
	char aiocbp_l_[PADL_(struct aiocb_c * __capability)]; struct aiocb_c * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability)];
};
struct cheriabi_aio_suspend_args {
	char aiocbp_l_[PADL_(struct aiocb_c * __capability const * __capability)]; struct aiocb_c * __capability const * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability const * __capability)];
	char nent_l_[PADL_(int)]; int nent; char nent_r_[PADR_(int)];
	char timeout_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability timeout; char timeout_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_aio_cancel_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char aiocbp_l_[PADL_(struct aiocb_c * __capability)]; struct aiocb_c * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability)];
};
struct cheriabi_aio_error_args {
	char aiocbp_l_[PADL_(struct aiocb_c * __capability)]; struct aiocb_c * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability)];
};
struct cheriabi___getcwd_args {
	char buf_l_[PADL_(char * __capability)]; char * __capability buf; char buf_r_[PADR_(char * __capability)];
	char buflen_l_[PADL_(size_t)]; size_t buflen; char buflen_r_[PADR_(size_t)];
};
struct cheriabi_sched_setparam_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char param_l_[PADL_(const struct sched_param * __capability)]; const struct sched_param * __capability param; char param_r_[PADR_(const struct sched_param * __capability)];
};
struct cheriabi_sched_getparam_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char param_l_[PADL_(struct sched_param * __capability)]; struct sched_param * __capability param; char param_r_[PADR_(struct sched_param * __capability)];
};
struct cheriabi_sched_setscheduler_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char policy_l_[PADL_(int)]; int policy; char policy_r_[PADR_(int)];
	char param_l_[PADL_(const struct sched_param * __capability)]; const struct sched_param * __capability param; char param_r_[PADR_(const struct sched_param * __capability)];
};
struct cheriabi_sched_rr_get_interval_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char interval_l_[PADL_(struct timespec * __capability)]; struct timespec * __capability interval; char interval_r_[PADR_(struct timespec * __capability)];
};
struct cheriabi_utrace_args {
	char addr_l_[PADL_(const void * __capability)]; const void * __capability addr; char addr_r_[PADR_(const void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
};
struct cheriabi_kldsym_args {
	char fileid_l_[PADL_(int)]; int fileid; char fileid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
};
struct cheriabi_jail_args {
	char jailp_l_[PADL_(struct jail_c * __capability)]; struct jail_c * __capability jailp; char jailp_r_[PADR_(struct jail_c * __capability)];
};
struct cheriabi_nnpfs_syscall_args {
	char operation_l_[PADL_(int)]; int operation; char operation_r_[PADR_(int)];
	char a_pathP_l_[PADL_(char * __capability)]; char * __capability a_pathP; char a_pathP_r_[PADR_(char * __capability)];
	char a_opcode_l_[PADL_(int)]; int a_opcode; char a_opcode_r_[PADR_(int)];
	char a_paramsP_l_[PADL_(void * __capability)]; void * __capability a_paramsP; char a_paramsP_r_[PADR_(void * __capability)];
	char a_followSymlinks_l_[PADL_(int)]; int a_followSymlinks; char a_followSymlinks_r_[PADR_(int)];
};
struct cheriabi_sigprocmask_args {
	char how_l_[PADL_(int)]; int how; char how_r_[PADR_(int)];
	char set_l_[PADL_(const sigset_t * __capability)]; const sigset_t * __capability set; char set_r_[PADR_(const sigset_t * __capability)];
	char oset_l_[PADL_(sigset_t * __capability)]; sigset_t * __capability oset; char oset_r_[PADR_(sigset_t * __capability)];
};
struct cheriabi_sigsuspend_args {
	char sigmask_l_[PADL_(const sigset_t * __capability)]; const sigset_t * __capability sigmask; char sigmask_r_[PADR_(const sigset_t * __capability)];
};
struct cheriabi_sigpending_args {
	char set_l_[PADL_(sigset_t * __capability)]; sigset_t * __capability set; char set_r_[PADR_(sigset_t * __capability)];
};
struct cheriabi_sigtimedwait_args {
	char set_l_[PADL_(const sigset_t * __capability)]; const sigset_t * __capability set; char set_r_[PADR_(const sigset_t * __capability)];
	char info_l_[PADL_(struct siginfo_c * __capability)]; struct siginfo_c * __capability info; char info_r_[PADR_(struct siginfo_c * __capability)];
	char timeout_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability timeout; char timeout_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_sigwaitinfo_args {
	char set_l_[PADL_(const sigset_t * __capability)]; const sigset_t * __capability set; char set_r_[PADR_(const sigset_t * __capability)];
	char info_l_[PADL_(struct siginfo_c * __capability)]; struct siginfo_c * __capability info; char info_r_[PADR_(struct siginfo_c * __capability)];
};
struct cheriabi___acl_get_file_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi___acl_set_file_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi___acl_get_fd_args {
	char filedes_l_[PADL_(int)]; int filedes; char filedes_r_[PADR_(int)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi___acl_set_fd_args {
	char filedes_l_[PADL_(int)]; int filedes; char filedes_r_[PADR_(int)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi___acl_delete_file_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
};
struct cheriabi___acl_aclcheck_file_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi___acl_aclcheck_fd_args {
	char filedes_l_[PADL_(int)]; int filedes; char filedes_r_[PADR_(int)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi_extattrctl_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char filename_l_[PADL_(const char * __capability)]; const char * __capability filename; char filename_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
};
struct cheriabi_extattr_set_file_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_extattr_get_file_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_extattr_delete_file_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
};
struct cheriabi_aio_waitcomplete_args {
	char aiocbp_l_[PADL_(struct aiocb_c * __capability * __capability)]; struct aiocb_c * __capability * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability * __capability)];
	char timeout_l_[PADL_(struct timespec * __capability)]; struct timespec * __capability timeout; char timeout_r_[PADR_(struct timespec * __capability)];
};
struct cheriabi_getresuid_args {
	char ruid_l_[PADL_(uid_t * __capability)]; uid_t * __capability ruid; char ruid_r_[PADR_(uid_t * __capability)];
	char euid_l_[PADL_(uid_t * __capability)]; uid_t * __capability euid; char euid_r_[PADR_(uid_t * __capability)];
	char suid_l_[PADL_(uid_t * __capability)]; uid_t * __capability suid; char suid_r_[PADR_(uid_t * __capability)];
};
struct cheriabi_getresgid_args {
	char rgid_l_[PADL_(gid_t * __capability)]; gid_t * __capability rgid; char rgid_r_[PADR_(gid_t * __capability)];
	char egid_l_[PADL_(gid_t * __capability)]; gid_t * __capability egid; char egid_r_[PADR_(gid_t * __capability)];
	char sgid_l_[PADL_(gid_t * __capability)]; gid_t * __capability sgid; char sgid_r_[PADR_(gid_t * __capability)];
};
struct cheriabi_extattr_set_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_extattr_get_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_extattr_delete_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
};
struct cheriabi_eaccess_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char amode_l_[PADL_(int)]; int amode; char amode_r_[PADR_(int)];
};
struct cheriabi_nmount_args {
	char iovp_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iovp; char iovp_r_[PADR_(struct iovec_c * __capability)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi___mac_get_proc_args {
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi___mac_set_proc_args {
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi___mac_get_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi___mac_get_file_args {
	char path_p_l_[PADL_(const char * __capability)]; const char * __capability path_p; char path_p_r_[PADR_(const char * __capability)];
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi___mac_set_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi___mac_set_file_args {
	char path_p_l_[PADL_(const char * __capability)]; const char * __capability path_p; char path_p_r_[PADR_(const char * __capability)];
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi_kenv_args {
	char what_l_[PADL_(int)]; int what; char what_r_[PADR_(int)];
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
	char value_l_[PADL_(char * __capability)]; char * __capability value; char value_r_[PADR_(char * __capability)];
	char len_l_[PADL_(int)]; int len; char len_r_[PADR_(int)];
};
struct cheriabi_lchflags_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(u_long)]; u_long flags; char flags_r_[PADR_(u_long)];
};
struct cheriabi_uuidgen_args {
	char store_l_[PADL_(struct uuid * __capability)]; struct uuid * __capability store; char store_r_[PADR_(struct uuid * __capability)];
	char count_l_[PADL_(int)]; int count; char count_r_[PADR_(int)];
};
struct cheriabi_sendfile_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
	char hdtr_l_[PADL_(struct sf_hdtr_c * __capability)]; struct sf_hdtr_c * __capability hdtr; char hdtr_r_[PADR_(struct sf_hdtr_c * __capability)];
	char sbytes_l_[PADL_(off_t * __capability)]; off_t * __capability sbytes; char sbytes_r_[PADR_(off_t * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_mac_syscall_args {
	char policy_l_[PADL_(const char * __capability)]; const char * __capability policy; char policy_r_[PADR_(const char * __capability)];
	char call_l_[PADL_(int)]; int call; char call_r_[PADR_(int)];
	char arg_l_[PADL_(void * __capability)]; void * __capability arg; char arg_r_[PADR_(void * __capability)];
};
struct cheriabi_ksem_init_args {
	char idp_l_[PADL_(semid_t * __capability)]; semid_t * __capability idp; char idp_r_[PADR_(semid_t * __capability)];
	char value_l_[PADL_(unsigned int)]; unsigned int value; char value_r_[PADR_(unsigned int)];
};
struct cheriabi_ksem_open_args {
	char idp_l_[PADL_(semid_t * __capability)]; semid_t * __capability idp; char idp_r_[PADR_(semid_t * __capability)];
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
	char oflag_l_[PADL_(int)]; int oflag; char oflag_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char value_l_[PADL_(unsigned int)]; unsigned int value; char value_r_[PADR_(unsigned int)];
};
struct cheriabi_ksem_unlink_args {
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
};
struct cheriabi_ksem_getvalue_args {
	char id_l_[PADL_(semid_t)]; semid_t id; char id_r_[PADR_(semid_t)];
	char val_l_[PADL_(int * __capability)]; int * __capability val; char val_r_[PADR_(int * __capability)];
};
struct cheriabi___mac_get_pid_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi___mac_get_link_args {
	char path_p_l_[PADL_(const char * __capability)]; const char * __capability path_p; char path_p_r_[PADR_(const char * __capability)];
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi___mac_set_link_args {
	char path_p_l_[PADL_(const char * __capability)]; const char * __capability path_p; char path_p_r_[PADR_(const char * __capability)];
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi_extattr_set_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_extattr_get_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_extattr_delete_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char attrname_l_[PADL_(const char * __capability)]; const char * __capability attrname; char attrname_r_[PADR_(const char * __capability)];
};
struct cheriabi___mac_execve_args {
	char fname_l_[PADL_(const char * __capability)]; const char * __capability fname; char fname_r_[PADR_(const char * __capability)];
	char argv_l_[PADL_(char * __capability * __capability)]; char * __capability * __capability argv; char argv_r_[PADR_(char * __capability * __capability)];
	char envv_l_[PADL_(char * __capability * __capability)]; char * __capability * __capability envv; char envv_r_[PADR_(char * __capability * __capability)];
	char mac_p_l_[PADL_(struct mac_c * __capability)]; struct mac_c * __capability mac_p; char mac_p_r_[PADR_(struct mac_c * __capability)];
};
struct cheriabi_sigaction_args {
	char sig_l_[PADL_(int)]; int sig; char sig_r_[PADR_(int)];
	char act_l_[PADL_(const struct sigaction_c * __capability)]; const struct sigaction_c * __capability act; char act_r_[PADR_(const struct sigaction_c * __capability)];
	char oact_l_[PADL_(struct sigaction_c * __capability)]; struct sigaction_c * __capability oact; char oact_r_[PADR_(struct sigaction_c * __capability)];
};
struct cheriabi_sigreturn_args {
	char sigcntxp_l_[PADL_(const struct __ucontext_c * __capability)]; const struct __ucontext_c * __capability sigcntxp; char sigcntxp_r_[PADR_(const struct __ucontext_c * __capability)];
};
struct cheriabi_getcontext_args {
	char ucp_l_[PADL_(struct __ucontext_c * __capability)]; struct __ucontext_c * __capability ucp; char ucp_r_[PADR_(struct __ucontext_c * __capability)];
};
struct cheriabi_setcontext_args {
	char ucp_l_[PADL_(const struct __ucontext_c * __capability)]; const struct __ucontext_c * __capability ucp; char ucp_r_[PADR_(const struct __ucontext_c * __capability)];
};
struct cheriabi_swapcontext_args {
	char oucp_l_[PADL_(struct __ucontext_c * __capability)]; struct __ucontext_c * __capability oucp; char oucp_r_[PADR_(struct __ucontext_c * __capability)];
	char ucp_l_[PADL_(const struct __ucontext_c * __capability)]; const struct __ucontext_c * __capability ucp; char ucp_r_[PADR_(const struct __ucontext_c * __capability)];
};
struct cheriabi_swapoff_args {
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
};
struct cheriabi___acl_get_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi___acl_set_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi___acl_delete_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
};
struct cheriabi___acl_aclcheck_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char type_l_[PADL_(acl_type_t)]; acl_type_t type; char type_r_[PADR_(acl_type_t)];
	char aclp_l_[PADL_(struct acl * __capability)]; struct acl * __capability aclp; char aclp_r_[PADR_(struct acl * __capability)];
};
struct cheriabi_sigwait_args {
	char set_l_[PADL_(const sigset_t * __capability)]; const sigset_t * __capability set; char set_r_[PADR_(const sigset_t * __capability)];
	char sig_l_[PADL_(int * __capability)]; int * __capability sig; char sig_r_[PADR_(int * __capability)];
};
struct cheriabi_thr_create_args {
	char ctx_l_[PADL_(struct __ucontext_c * __capability)]; struct __ucontext_c * __capability ctx; char ctx_r_[PADR_(struct __ucontext_c * __capability)];
	char id_l_[PADL_(long * __capability)]; long * __capability id; char id_r_[PADR_(long * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_thr_exit_args {
	char state_l_[PADL_(long * __capability)]; long * __capability state; char state_r_[PADR_(long * __capability)];
};
struct cheriabi_thr_self_args {
	char id_l_[PADL_(long * __capability)]; long * __capability id; char id_r_[PADR_(long * __capability)];
};
struct cheriabi_extattr_list_fd_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_extattr_list_file_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_extattr_list_link_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char attrnamespace_l_[PADL_(int)]; int attrnamespace; char attrnamespace_r_[PADR_(int)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
};
struct cheriabi_ksem_timedwait_args {
	char id_l_[PADL_(semid_t)]; semid_t id; char id_r_[PADR_(semid_t)];
	char abstime_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability abstime; char abstime_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_thr_suspend_args {
	char timeout_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability timeout; char timeout_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_audit_args {
	char record_l_[PADL_(const void * __capability)]; const void * __capability record; char record_r_[PADR_(const void * __capability)];
	char length_l_[PADL_(u_int)]; u_int length; char length_r_[PADR_(u_int)];
};
struct cheriabi_auditon_args {
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
	char length_l_[PADL_(u_int)]; u_int length; char length_r_[PADR_(u_int)];
};
struct cheriabi_getauid_args {
	char auid_l_[PADL_(uid_t * __capability)]; uid_t * __capability auid; char auid_r_[PADR_(uid_t * __capability)];
};
struct cheriabi_setauid_args {
	char auid_l_[PADL_(uid_t * __capability)]; uid_t * __capability auid; char auid_r_[PADR_(uid_t * __capability)];
};
struct cheriabi_getaudit_args {
	char auditinfo_l_[PADL_(struct auditinfo * __capability)]; struct auditinfo * __capability auditinfo; char auditinfo_r_[PADR_(struct auditinfo * __capability)];
};
struct cheriabi_setaudit_args {
	char auditinfo_l_[PADL_(struct auditinfo * __capability)]; struct auditinfo * __capability auditinfo; char auditinfo_r_[PADR_(struct auditinfo * __capability)];
};
struct cheriabi_getaudit_addr_args {
	char auditinfo_addr_l_[PADL_(struct auditinfo_addr * __capability)]; struct auditinfo_addr * __capability auditinfo_addr; char auditinfo_addr_r_[PADR_(struct auditinfo_addr * __capability)];
	char length_l_[PADL_(u_int)]; u_int length; char length_r_[PADR_(u_int)];
};
struct cheriabi_setaudit_addr_args {
	char auditinfo_addr_l_[PADL_(struct auditinfo_addr * __capability)]; struct auditinfo_addr * __capability auditinfo_addr; char auditinfo_addr_r_[PADR_(struct auditinfo_addr * __capability)];
	char length_l_[PADL_(u_int)]; u_int length; char length_r_[PADR_(u_int)];
};
struct cheriabi_auditctl_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi__umtx_op_args {
	char obj_l_[PADL_(void * __capability)]; void * __capability obj; char obj_r_[PADR_(void * __capability)];
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char val_l_[PADL_(u_long)]; u_long val; char val_r_[PADR_(u_long)];
	char uaddr1_l_[PADL_(void * __capability)]; void * __capability uaddr1; char uaddr1_r_[PADR_(void * __capability)];
	char uaddr2_l_[PADL_(void * __capability)]; void * __capability uaddr2; char uaddr2_r_[PADR_(void * __capability)];
};
struct cheriabi_thr_new_args {
	char param_l_[PADL_(struct thr_param_c * __capability)]; struct thr_param_c * __capability param; char param_r_[PADR_(struct thr_param_c * __capability)];
	char param_size_l_[PADL_(int)]; int param_size; char param_size_r_[PADR_(int)];
};
struct cheriabi_sigqueue_args {
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char signum_l_[PADL_(int)]; int signum; char signum_r_[PADR_(int)];
	char value_l_[PADL_(void * __capability)]; void * __capability value; char value_r_[PADR_(void * __capability)];
};
struct cheriabi_kmq_open_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char attr_l_[PADL_(const struct mq_attr * __capability)]; const struct mq_attr * __capability attr; char attr_r_[PADR_(const struct mq_attr * __capability)];
};
struct cheriabi_kmq_setattr_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char attr_l_[PADL_(const struct mq_attr * __capability)]; const struct mq_attr * __capability attr; char attr_r_[PADR_(const struct mq_attr * __capability)];
	char oattr_l_[PADL_(struct mq_attr * __capability)]; struct mq_attr * __capability oattr; char oattr_r_[PADR_(struct mq_attr * __capability)];
};
struct cheriabi_kmq_timedreceive_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char msg_ptr_l_[PADL_(char * __capability)]; char * __capability msg_ptr; char msg_ptr_r_[PADR_(char * __capability)];
	char msg_len_l_[PADL_(size_t)]; size_t msg_len; char msg_len_r_[PADR_(size_t)];
	char msg_prio_l_[PADL_(unsigned * __capability)]; unsigned * __capability msg_prio; char msg_prio_r_[PADR_(unsigned * __capability)];
	char abs_timeout_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability abs_timeout; char abs_timeout_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_kmq_timedsend_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char msg_ptr_l_[PADL_(const char * __capability)]; const char * __capability msg_ptr; char msg_ptr_r_[PADR_(const char * __capability)];
	char msg_len_l_[PADL_(size_t)]; size_t msg_len; char msg_len_r_[PADR_(size_t)];
	char msg_prio_l_[PADL_(unsigned)]; unsigned msg_prio; char msg_prio_r_[PADR_(unsigned)];
	char abs_timeout_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability abs_timeout; char abs_timeout_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_kmq_notify_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char sigev_l_[PADL_(const struct sigevent_c * __capability)]; const struct sigevent_c * __capability sigev; char sigev_r_[PADR_(const struct sigevent_c * __capability)];
};
struct cheriabi_kmq_unlink_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_abort2_args {
	char why_l_[PADL_(const char * __capability)]; const char * __capability why; char why_r_[PADR_(const char * __capability)];
	char nargs_l_[PADL_(int)]; int nargs; char nargs_r_[PADR_(int)];
	char args_l_[PADL_(void * __capability * __capability)]; void * __capability * __capability args; char args_r_[PADR_(void * __capability * __capability)];
};
struct cheriabi_thr_set_name_args {
	char id_l_[PADL_(long)]; long id; char id_r_[PADR_(long)];
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
};
struct cheriabi_aio_fsync_args {
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char aiocbp_l_[PADL_(struct aiocb_c * __capability)]; struct aiocb_c * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability)];
};
struct cheriabi_rtprio_thread_args {
	char function_l_[PADL_(int)]; int function; char function_r_[PADR_(int)];
	char lwpid_l_[PADL_(lwpid_t)]; lwpid_t lwpid; char lwpid_r_[PADR_(lwpid_t)];
	char rtp_l_[PADL_(struct rtprio * __capability)]; struct rtprio * __capability rtp; char rtp_r_[PADR_(struct rtprio * __capability)];
};
struct cheriabi_sctp_generic_sendmsg_args {
	char sd_l_[PADL_(int)]; int sd; char sd_r_[PADR_(int)];
	char msg_l_[PADL_(void * __capability)]; void * __capability msg; char msg_r_[PADR_(void * __capability)];
	char mlen_l_[PADL_(int)]; int mlen; char mlen_r_[PADR_(int)];
	char to_l_[PADL_(const struct sockaddr * __capability)]; const struct sockaddr * __capability to; char to_r_[PADR_(const struct sockaddr * __capability)];
	char tolen_l_[PADL_(__socklen_t)]; __socklen_t tolen; char tolen_r_[PADR_(__socklen_t)];
	char sinfo_l_[PADL_(struct sctp_sndrcvinfo * __capability)]; struct sctp_sndrcvinfo * __capability sinfo; char sinfo_r_[PADR_(struct sctp_sndrcvinfo * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_sctp_generic_sendmsg_iov_args {
	char sd_l_[PADL_(int)]; int sd; char sd_r_[PADR_(int)];
	char iov_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iov; char iov_r_[PADR_(struct iovec_c * __capability)];
	char iovlen_l_[PADL_(int)]; int iovlen; char iovlen_r_[PADR_(int)];
	char to_l_[PADL_(const struct sockaddr * __capability)]; const struct sockaddr * __capability to; char to_r_[PADR_(const struct sockaddr * __capability)];
	char tolen_l_[PADL_(__socklen_t)]; __socklen_t tolen; char tolen_r_[PADR_(__socklen_t)];
	char sinfo_l_[PADL_(struct sctp_sndrcvinfo * __capability)]; struct sctp_sndrcvinfo * __capability sinfo; char sinfo_r_[PADR_(struct sctp_sndrcvinfo * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_sctp_generic_recvmsg_args {
	char sd_l_[PADL_(int)]; int sd; char sd_r_[PADR_(int)];
	char iov_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iov; char iov_r_[PADR_(struct iovec_c * __capability)];
	char iovlen_l_[PADL_(int)]; int iovlen; char iovlen_r_[PADR_(int)];
	char from_l_[PADL_(struct sockaddr * __capability)]; struct sockaddr * __capability from; char from_r_[PADR_(struct sockaddr * __capability)];
	char fromlenaddr_l_[PADL_(__socklen_t * __capability)]; __socklen_t * __capability fromlenaddr; char fromlenaddr_r_[PADR_(__socklen_t * __capability)];
	char sinfo_l_[PADL_(struct sctp_sndrcvinfo * __capability)]; struct sctp_sndrcvinfo * __capability sinfo; char sinfo_r_[PADR_(struct sctp_sndrcvinfo * __capability)];
	char msg_flags_l_[PADL_(int * __capability)]; int * __capability msg_flags; char msg_flags_r_[PADR_(int * __capability)];
};
struct cheriabi_pread_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(void * __capability)]; void * __capability buf; char buf_r_[PADR_(void * __capability)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct cheriabi_pwrite_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(const void * __capability)]; const void * __capability buf; char buf_r_[PADR_(const void * __capability)];
	char nbyte_l_[PADL_(size_t)]; size_t nbyte; char nbyte_r_[PADR_(size_t)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct cheriabi_mmap_args {
	char addr_l_[PADL_(void * __capability)]; void * __capability addr; char addr_r_[PADR_(void * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char prot_l_[PADL_(int)]; int prot; char prot_r_[PADR_(int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char pos_l_[PADL_(off_t)]; off_t pos; char pos_r_[PADR_(off_t)];
};
struct cheriabi_truncate_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char length_l_[PADL_(off_t)]; off_t length; char length_r_[PADR_(off_t)];
};
struct cheriabi_shm_unlink_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_cpuset_args {
	char setid_l_[PADL_(cpusetid_t * __capability)]; cpusetid_t * __capability setid; char setid_r_[PADR_(cpusetid_t * __capability)];
};
struct cheriabi_cpuset_getid_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char setid_l_[PADL_(cpusetid_t * __capability)]; cpusetid_t * __capability setid; char setid_r_[PADR_(cpusetid_t * __capability)];
};
struct cheriabi_cpuset_getaffinity_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char cpusetsize_l_[PADL_(size_t)]; size_t cpusetsize; char cpusetsize_r_[PADR_(size_t)];
	char mask_l_[PADL_(cpuset_t * __capability)]; cpuset_t * __capability mask; char mask_r_[PADR_(cpuset_t * __capability)];
};
struct cheriabi_cpuset_setaffinity_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char cpusetsize_l_[PADL_(size_t)]; size_t cpusetsize; char cpusetsize_r_[PADR_(size_t)];
	char mask_l_[PADL_(const cpuset_t * __capability)]; const cpuset_t * __capability mask; char mask_r_[PADR_(const cpuset_t * __capability)];
};
struct cheriabi_faccessat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char amode_l_[PADL_(int)]; int amode; char amode_r_[PADR_(int)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct cheriabi_fchmodat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct cheriabi_fchownat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char uid_l_[PADL_(uid_t)]; uid_t uid; char uid_r_[PADR_(uid_t)];
	char gid_l_[PADL_(gid_t)]; gid_t gid; char gid_r_[PADR_(gid_t)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct cheriabi_fexecve_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char argv_l_[PADL_(char * __capability * __capability)]; char * __capability * __capability argv; char argv_r_[PADR_(char * __capability * __capability)];
	char envv_l_[PADL_(char * __capability * __capability)]; char * __capability * __capability envv; char envv_r_[PADR_(char * __capability * __capability)];
};
struct cheriabi_futimesat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char times_l_[PADL_(const struct timeval * __capability)]; const struct timeval * __capability times; char times_r_[PADR_(const struct timeval * __capability)];
};
struct cheriabi_linkat_args {
	char fd1_l_[PADL_(int)]; int fd1; char fd1_r_[PADR_(int)];
	char path1_l_[PADL_(const char * __capability)]; const char * __capability path1; char path1_r_[PADR_(const char * __capability)];
	char fd2_l_[PADL_(int)]; int fd2; char fd2_r_[PADR_(int)];
	char path2_l_[PADL_(const char * __capability)]; const char * __capability path2; char path2_r_[PADR_(const char * __capability)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct cheriabi_mkdirat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct cheriabi_mkfifoat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct cheriabi_openat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
struct cheriabi_readlinkat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char buf_l_[PADL_(char * __capability)]; char * __capability buf; char buf_r_[PADR_(char * __capability)];
	char bufsize_l_[PADL_(size_t)]; size_t bufsize; char bufsize_r_[PADR_(size_t)];
};
struct cheriabi_renameat_args {
	char oldfd_l_[PADL_(int)]; int oldfd; char oldfd_r_[PADR_(int)];
	char old_l_[PADL_(const char * __capability)]; const char * __capability old; char old_r_[PADR_(const char * __capability)];
	char newfd_l_[PADL_(int)]; int newfd; char newfd_r_[PADR_(int)];
	char new_l_[PADL_(const char * __capability)]; const char * __capability new; char new_r_[PADR_(const char * __capability)];
};
struct cheriabi_symlinkat_args {
	char path1_l_[PADL_(const char * __capability)]; const char * __capability path1; char path1_r_[PADR_(const char * __capability)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path2_l_[PADL_(const char * __capability)]; const char * __capability path2; char path2_r_[PADR_(const char * __capability)];
};
struct cheriabi_unlinkat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct cheriabi_gssd_syscall_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
struct cheriabi_jail_get_args {
	char iovp_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iovp; char iovp_r_[PADR_(struct iovec_c * __capability)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_jail_set_args {
	char iovp_l_[PADL_(struct iovec_c * __capability)]; struct iovec_c * __capability iovp; char iovp_r_[PADR_(struct iovec_c * __capability)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi___semctl_args {
	char semid_l_[PADL_(int)]; int semid; char semid_r_[PADR_(int)];
	char semnum_l_[PADL_(int)]; int semnum; char semnum_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char arg_l_[PADL_(union semun_c * __capability)]; union semun_c * __capability arg; char arg_r_[PADR_(union semun_c * __capability)];
};
struct cheriabi_msgctl_args {
	char msqid_l_[PADL_(int)]; int msqid; char msqid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char buf_l_[PADL_(struct msqid_ds_c * __capability)]; struct msqid_ds_c * __capability buf; char buf_r_[PADR_(struct msqid_ds_c * __capability)];
};
struct cheriabi_shmctl_args {
	char shmid_l_[PADL_(int)]; int shmid; char shmid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char buf_l_[PADL_(struct shmid_ds * __capability)]; struct shmid_ds * __capability buf; char buf_r_[PADR_(struct shmid_ds * __capability)];
};
struct cheriabi_lpathconf_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char name_l_[PADL_(int)]; int name; char name_r_[PADR_(int)];
};
struct cheriabi___cap_rights_get_args {
	char version_l_[PADL_(int)]; int version; char version_r_[PADR_(int)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char rightsp_l_[PADL_(cap_rights_t * __capability)]; cap_rights_t * __capability rightsp; char rightsp_r_[PADR_(cap_rights_t * __capability)];
};
struct cheriabi_cap_getmode_args {
	char modep_l_[PADL_(u_int * __capability)]; u_int * __capability modep; char modep_r_[PADR_(u_int * __capability)];
};
struct cheriabi_pdfork_args {
	char fdp_l_[PADL_(int * __capability)]; int * __capability fdp; char fdp_r_[PADR_(int * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_pdgetpid_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char pidp_l_[PADL_(pid_t * __capability)]; pid_t * __capability pidp; char pidp_r_[PADR_(pid_t * __capability)];
};
struct cheriabi_pselect_args {
	char nd_l_[PADL_(int)]; int nd; char nd_r_[PADR_(int)];
	char in_l_[PADL_(fd_set * __capability)]; fd_set * __capability in; char in_r_[PADR_(fd_set * __capability)];
	char ou_l_[PADL_(fd_set * __capability)]; fd_set * __capability ou; char ou_r_[PADR_(fd_set * __capability)];
	char ex_l_[PADL_(fd_set * __capability)]; fd_set * __capability ex; char ex_r_[PADR_(fd_set * __capability)];
	char ts_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability ts; char ts_r_[PADR_(const struct timespec * __capability)];
	char sm_l_[PADL_(const sigset_t * __capability)]; const sigset_t * __capability sm; char sm_r_[PADR_(const sigset_t * __capability)];
};
struct cheriabi_getloginclass_args {
	char namebuf_l_[PADL_(char * __capability)]; char * __capability namebuf; char namebuf_r_[PADR_(char * __capability)];
	char namelen_l_[PADL_(size_t)]; size_t namelen; char namelen_r_[PADR_(size_t)];
};
struct cheriabi_setloginclass_args {
	char namebuf_l_[PADL_(const char * __capability)]; const char * __capability namebuf; char namebuf_r_[PADR_(const char * __capability)];
};
struct cheriabi_rctl_get_racct_args {
	char inbufp_l_[PADL_(const void * __capability)]; const void * __capability inbufp; char inbufp_r_[PADR_(const void * __capability)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void * __capability)]; void * __capability outbufp; char outbufp_r_[PADR_(void * __capability)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct cheriabi_rctl_get_rules_args {
	char inbufp_l_[PADL_(const void * __capability)]; const void * __capability inbufp; char inbufp_r_[PADR_(const void * __capability)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void * __capability)]; void * __capability outbufp; char outbufp_r_[PADR_(void * __capability)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct cheriabi_rctl_get_limits_args {
	char inbufp_l_[PADL_(const void * __capability)]; const void * __capability inbufp; char inbufp_r_[PADR_(const void * __capability)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void * __capability)]; void * __capability outbufp; char outbufp_r_[PADR_(void * __capability)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct cheriabi_rctl_add_rule_args {
	char inbufp_l_[PADL_(const void * __capability)]; const void * __capability inbufp; char inbufp_r_[PADR_(const void * __capability)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void * __capability)]; void * __capability outbufp; char outbufp_r_[PADR_(void * __capability)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct cheriabi_rctl_remove_rule_args {
	char inbufp_l_[PADL_(const void * __capability)]; const void * __capability inbufp; char inbufp_r_[PADR_(const void * __capability)];
	char inbuflen_l_[PADL_(size_t)]; size_t inbuflen; char inbuflen_r_[PADR_(size_t)];
	char outbufp_l_[PADL_(void * __capability)]; void * __capability outbufp; char outbufp_r_[PADR_(void * __capability)];
	char outbuflen_l_[PADL_(size_t)]; size_t outbuflen; char outbuflen_r_[PADR_(size_t)];
};
struct cheriabi_wait6_args {
	char idtype_l_[PADL_(idtype_t)]; idtype_t idtype; char idtype_r_[PADR_(idtype_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char status_l_[PADL_(int * __capability)]; int * __capability status; char status_r_[PADR_(int * __capability)];
	char options_l_[PADL_(int)]; int options; char options_r_[PADR_(int)];
	char wrusage_l_[PADL_(struct __wrusage * __capability)]; struct __wrusage * __capability wrusage; char wrusage_r_[PADR_(struct __wrusage * __capability)];
	char info_l_[PADL_(struct siginfo_c * __capability)]; struct siginfo_c * __capability info; char info_r_[PADR_(struct siginfo_c * __capability)];
};
struct cheriabi_cap_rights_limit_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char rightsp_l_[PADL_(cap_rights_t * __capability)]; cap_rights_t * __capability rightsp; char rightsp_r_[PADR_(cap_rights_t * __capability)];
};
struct cheriabi_cap_ioctls_limit_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmds_l_[PADL_(const u_long * __capability)]; const u_long * __capability cmds; char cmds_r_[PADR_(const u_long * __capability)];
	char ncmds_l_[PADL_(size_t)]; size_t ncmds; char ncmds_r_[PADR_(size_t)];
};
struct cheriabi_cap_ioctls_get_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmds_l_[PADL_(u_long * __capability)]; u_long * __capability cmds; char cmds_r_[PADR_(u_long * __capability)];
	char maxcmds_l_[PADL_(size_t)]; size_t maxcmds; char maxcmds_r_[PADR_(size_t)];
};
struct cheriabi_cap_fcntls_get_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char fcntlrightsp_l_[PADL_(uint32_t * __capability)]; uint32_t * __capability fcntlrightsp; char fcntlrightsp_r_[PADR_(uint32_t * __capability)];
};
struct cheriabi_bindat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(const struct sockaddr * __capability)]; const struct sockaddr * __capability name; char name_r_[PADR_(const struct sockaddr * __capability)];
	char namelen_l_[PADL_(__socklen_t)]; __socklen_t namelen; char namelen_r_[PADR_(__socklen_t)];
};
struct cheriabi_connectat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(const struct sockaddr * __capability)]; const struct sockaddr * __capability name; char name_r_[PADR_(const struct sockaddr * __capability)];
	char namelen_l_[PADL_(__socklen_t)]; __socklen_t namelen; char namelen_r_[PADR_(__socklen_t)];
};
struct cheriabi_chflagsat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(u_long)]; u_long flags; char flags_r_[PADR_(u_long)];
	char atflag_l_[PADL_(int)]; int atflag; char atflag_r_[PADR_(int)];
};
struct cheriabi_accept4_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char name_l_[PADL_(struct sockaddr * __capability)]; struct sockaddr * __capability name; char name_r_[PADR_(struct sockaddr * __capability)];
	char anamelen_l_[PADL_(__socklen_t * __capability)]; __socklen_t * __capability anamelen; char anamelen_r_[PADR_(__socklen_t * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_pipe2_args {
	char fildes_l_[PADL_(int * __capability)]; int * __capability fildes; char fildes_r_[PADR_(int * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_aio_mlock_args {
	char aiocbp_l_[PADL_(struct aiocb_c * __capability)]; struct aiocb_c * __capability aiocbp; char aiocbp_r_[PADR_(struct aiocb_c * __capability)];
};
struct cheriabi_procctl_args {
	char idtype_l_[PADL_(idtype_t)]; idtype_t idtype; char idtype_r_[PADR_(idtype_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char com_l_[PADL_(int)]; int com; char com_r_[PADR_(int)];
	char data_l_[PADL_(void * __capability)]; void * __capability data; char data_r_[PADR_(void * __capability)];
};
struct cheriabi_ppoll_args {
	char fds_l_[PADL_(struct pollfd * __capability)]; struct pollfd * __capability fds; char fds_r_[PADR_(struct pollfd * __capability)];
	char nfds_l_[PADL_(u_int)]; u_int nfds; char nfds_r_[PADR_(u_int)];
	char ts_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability ts; char ts_r_[PADR_(const struct timespec * __capability)];
	char set_l_[PADL_(const sigset_t * __capability)]; const sigset_t * __capability set; char set_r_[PADR_(const sigset_t * __capability)];
};
struct cheriabi_futimens_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char times_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability times; char times_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_utimensat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char times_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability times; char times_r_[PADR_(const struct timespec * __capability)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct cheriabi_fstat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char sb_l_[PADL_(struct stat * __capability)]; struct stat * __capability sb; char sb_r_[PADR_(struct stat * __capability)];
};
struct cheriabi_fstatat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char buf_l_[PADL_(struct stat * __capability)]; struct stat * __capability buf; char buf_r_[PADR_(struct stat * __capability)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct cheriabi_fhstat_args {
	char u_fhp_l_[PADL_(const struct fhandle * __capability)]; const struct fhandle * __capability u_fhp; char u_fhp_r_[PADR_(const struct fhandle * __capability)];
	char sb_l_[PADL_(struct stat * __capability)]; struct stat * __capability sb; char sb_r_[PADR_(struct stat * __capability)];
};
struct cheriabi_getdirentries_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(char * __capability)]; char * __capability buf; char buf_r_[PADR_(char * __capability)];
	char count_l_[PADL_(size_t)]; size_t count; char count_r_[PADR_(size_t)];
	char basep_l_[PADL_(off_t * __capability)]; off_t * __capability basep; char basep_r_[PADR_(off_t * __capability)];
};
struct cheriabi_statfs_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char buf_l_[PADL_(struct statfs * __capability)]; struct statfs * __capability buf; char buf_r_[PADR_(struct statfs * __capability)];
};
struct cheriabi_fstatfs_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char buf_l_[PADL_(struct statfs * __capability)]; struct statfs * __capability buf; char buf_r_[PADR_(struct statfs * __capability)];
};
struct cheriabi_getfsstat_args {
	char buf_l_[PADL_(struct statfs * __capability)]; struct statfs * __capability buf; char buf_r_[PADR_(struct statfs * __capability)];
	char bufsize_l_[PADL_(long)]; long bufsize; char bufsize_r_[PADR_(long)];
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
};
struct cheriabi_fhstatfs_args {
	char u_fhp_l_[PADL_(const struct fhandle * __capability)]; const struct fhandle * __capability u_fhp; char u_fhp_r_[PADR_(const struct fhandle * __capability)];
	char buf_l_[PADL_(struct statfs * __capability)]; struct statfs * __capability buf; char buf_r_[PADR_(struct statfs * __capability)];
};
struct cheriabi_mknodat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char dev_l_[PADL_(dev_t)]; dev_t dev; char dev_r_[PADR_(dev_t)];
};
struct cheriabi_kevent_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char changelist_l_[PADL_(const struct kevent_c * __capability)]; const struct kevent_c * __capability changelist; char changelist_r_[PADR_(const struct kevent_c * __capability)];
	char nchanges_l_[PADL_(int)]; int nchanges; char nchanges_r_[PADR_(int)];
	char eventlist_l_[PADL_(struct kevent_c * __capability)]; struct kevent_c * __capability eventlist; char eventlist_r_[PADR_(struct kevent_c * __capability)];
	char nevents_l_[PADL_(int)]; int nevents; char nevents_r_[PADR_(int)];
	char timeout_l_[PADL_(const struct timespec * __capability)]; const struct timespec * __capability timeout; char timeout_r_[PADR_(const struct timespec * __capability)];
};
struct cheriabi_cpuset_getdomain_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char domainsetsize_l_[PADL_(size_t)]; size_t domainsetsize; char domainsetsize_r_[PADR_(size_t)];
	char mask_l_[PADL_(domainset_t * __capability)]; domainset_t * __capability mask; char mask_r_[PADR_(domainset_t * __capability)];
	char policy_l_[PADL_(int * __capability)]; int * __capability policy; char policy_r_[PADR_(int * __capability)];
};
struct cheriabi_cpuset_setdomain_args {
	char level_l_[PADL_(cpulevel_t)]; cpulevel_t level; char level_r_[PADR_(cpulevel_t)];
	char which_l_[PADL_(cpuwhich_t)]; cpuwhich_t which; char which_r_[PADR_(cpuwhich_t)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char domainsetsize_l_[PADL_(size_t)]; size_t domainsetsize; char domainsetsize_r_[PADR_(size_t)];
	char mask_l_[PADL_(domainset_t * __capability)]; domainset_t * __capability mask; char mask_r_[PADR_(domainset_t * __capability)];
	char policy_l_[PADL_(int)]; int policy; char policy_r_[PADR_(int)];
};
struct cheriabi_getrandom_args {
	char buf_l_[PADL_(void * __capability)]; void * __capability buf; char buf_r_[PADR_(void * __capability)];
	char buflen_l_[PADL_(size_t)]; size_t buflen; char buflen_r_[PADR_(size_t)];
	char flags_l_[PADL_(unsigned int)]; unsigned int flags; char flags_r_[PADR_(unsigned int)];
};
struct cheriabi_getfhat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(char * __capability)]; char * __capability path; char path_r_[PADR_(char * __capability)];
	char fhp_l_[PADL_(struct fhandle * __capability)]; struct fhandle * __capability fhp; char fhp_r_[PADR_(struct fhandle * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_fhlink_args {
	char fhp_l_[PADL_(struct fhandle * __capability)]; struct fhandle * __capability fhp; char fhp_r_[PADR_(struct fhandle * __capability)];
	char to_l_[PADL_(const char * __capability)]; const char * __capability to; char to_r_[PADR_(const char * __capability)];
};
struct cheriabi_fhlinkat_args {
	char fhp_l_[PADL_(struct fhandle * __capability)]; struct fhandle * __capability fhp; char fhp_r_[PADR_(struct fhandle * __capability)];
	char tofd_l_[PADL_(int)]; int tofd; char tofd_r_[PADR_(int)];
	char to_l_[PADL_(const char * __capability)]; const char * __capability to; char to_r_[PADR_(const char * __capability)];
};
struct cheriabi_fhreadlink_args {
	char fhp_l_[PADL_(struct fhandle * __capability)]; struct fhandle * __capability fhp; char fhp_r_[PADR_(struct fhandle * __capability)];
	char buf_l_[PADL_(char * __capability)]; char * __capability buf; char buf_r_[PADR_(char * __capability)];
	char bufsize_l_[PADL_(size_t)]; size_t bufsize; char bufsize_r_[PADR_(size_t)];
};
struct cheriabi_funlinkat_args {
	char dfd_l_[PADL_(int)]; int dfd; char dfd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char flag_l_[PADL_(int)]; int flag; char flag_r_[PADR_(int)];
};
struct cheriabi_copy_file_range_args {
	char infd_l_[PADL_(int)]; int infd; char infd_r_[PADR_(int)];
	char inoffp_l_[PADL_(off_t * __capability)]; off_t * __capability inoffp; char inoffp_r_[PADR_(off_t * __capability)];
	char outfd_l_[PADL_(int)]; int outfd; char outfd_r_[PADR_(int)];
	char outoffp_l_[PADL_(off_t * __capability)]; off_t * __capability outoffp; char outoffp_r_[PADR_(off_t * __capability)];
	char len_l_[PADL_(size_t)]; size_t len; char len_r_[PADR_(size_t)];
	char flags_l_[PADL_(unsigned int)]; unsigned int flags; char flags_r_[PADR_(unsigned int)];
};
struct cheriabi___sysctlbyname_args {
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
	char namelen_l_[PADL_(size_t)]; size_t namelen; char namelen_r_[PADR_(size_t)];
	char old_l_[PADL_(void * __capability)]; void * __capability old; char old_r_[PADR_(void * __capability)];
	char oldlenp_l_[PADL_(size_t * __capability)]; size_t * __capability oldlenp; char oldlenp_r_[PADR_(size_t * __capability)];
	char new_l_[PADL_(void * __capability)]; void * __capability new; char new_r_[PADR_(void * __capability)];
	char newlen_l_[PADL_(size_t)]; size_t newlen; char newlen_r_[PADR_(size_t)];
};
struct cheriabi_shm_open2_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
	char shmflags_l_[PADL_(int)]; int shmflags; char shmflags_r_[PADR_(int)];
	char name_l_[PADL_(const char * __capability)]; const char * __capability name; char name_r_[PADR_(const char * __capability)];
};
struct cheriabi_shm_rename_args {
	char path_from_l_[PADL_(const char * __capability)]; const char * __capability path_from; char path_from_r_[PADR_(const char * __capability)];
	char path_to_l_[PADL_(const char * __capability)]; const char * __capability path_to; char path_to_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_sigfastblock_args {
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char ptr_l_[PADL_(uint32_t * __capability)]; uint32_t * __capability ptr; char ptr_r_[PADR_(uint32_t * __capability)];
};
struct cheriabi___realpathat_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char buf_l_[PADL_(char * __capability)]; char * __capability buf; char buf_r_[PADR_(char * __capability)];
	char size_l_[PADL_(size_t)]; size_t size; char size_r_[PADR_(size_t)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_rpctls_syscall_args {
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
};
int	cheriabi_read(struct thread *, struct cheriabi_read_args *);
int	cheriabi_write(struct thread *, struct cheriabi_write_args *);
int	cheriabi_open(struct thread *, struct cheriabi_open_args *);
int	cheriabi_wait4(struct thread *, struct cheriabi_wait4_args *);
int	cheriabi_link(struct thread *, struct cheriabi_link_args *);
int	cheriabi_unlink(struct thread *, struct cheriabi_unlink_args *);
int	cheriabi_chdir(struct thread *, struct cheriabi_chdir_args *);
int	cheriabi_chmod(struct thread *, struct cheriabi_chmod_args *);
int	cheriabi_chown(struct thread *, struct cheriabi_chown_args *);
int	cheriabi_mount(struct thread *, struct cheriabi_mount_args *);
int	cheriabi_unmount(struct thread *, struct cheriabi_unmount_args *);
int	cheriabi_ptrace(struct thread *, struct cheriabi_ptrace_args *);
int	cheriabi_recvmsg(struct thread *, struct cheriabi_recvmsg_args *);
int	cheriabi_sendmsg(struct thread *, struct cheriabi_sendmsg_args *);
int	cheriabi_recvfrom(struct thread *, struct cheriabi_recvfrom_args *);
int	cheriabi_accept(struct thread *, struct cheriabi_accept_args *);
int	cheriabi_getpeername(struct thread *, struct cheriabi_getpeername_args *);
int	cheriabi_getsockname(struct thread *, struct cheriabi_getsockname_args *);
int	cheriabi_access(struct thread *, struct cheriabi_access_args *);
int	cheriabi_chflags(struct thread *, struct cheriabi_chflags_args *);
int	cheriabi_profil(struct thread *, struct cheriabi_profil_args *);
int	cheriabi_ktrace(struct thread *, struct cheriabi_ktrace_args *);
int	cheriabi_getlogin(struct thread *, struct cheriabi_getlogin_args *);
int	cheriabi_setlogin(struct thread *, struct cheriabi_setlogin_args *);
int	cheriabi_acct(struct thread *, struct cheriabi_acct_args *);
int	cheriabi_sigaltstack(struct thread *, struct cheriabi_sigaltstack_args *);
int	cheriabi_ioctl(struct thread *, struct cheriabi_ioctl_args *);
int	cheriabi_revoke(struct thread *, struct cheriabi_revoke_args *);
int	cheriabi_symlink(struct thread *, struct cheriabi_symlink_args *);
int	cheriabi_readlink(struct thread *, struct cheriabi_readlink_args *);
int	cheriabi_execve(struct thread *, struct cheriabi_execve_args *);
int	cheriabi_chroot(struct thread *, struct cheriabi_chroot_args *);
int	cheriabi_msync(struct thread *, struct cheriabi_msync_args *);
int	cheriabi_munmap(struct thread *, struct cheriabi_munmap_args *);
int	cheriabi_mprotect(struct thread *, struct cheriabi_mprotect_args *);
int	cheriabi_madvise(struct thread *, struct cheriabi_madvise_args *);
int	cheriabi_mincore(struct thread *, struct cheriabi_mincore_args *);
int	cheriabi_getgroups(struct thread *, struct cheriabi_getgroups_args *);
int	cheriabi_setgroups(struct thread *, struct cheriabi_setgroups_args *);
int	cheriabi_setitimer(struct thread *, struct cheriabi_setitimer_args *);
int	cheriabi_swapon(struct thread *, struct cheriabi_swapon_args *);
int	cheriabi_getitimer(struct thread *, struct cheriabi_getitimer_args *);
int	cheriabi_fcntl(struct thread *, struct cheriabi_fcntl_args *);
int	cheriabi_select(struct thread *, struct cheriabi_select_args *);
int	cheriabi_connect(struct thread *, struct cheriabi_connect_args *);
int	cheriabi_bind(struct thread *, struct cheriabi_bind_args *);
int	cheriabi_setsockopt(struct thread *, struct cheriabi_setsockopt_args *);
int	cheriabi_gettimeofday(struct thread *, struct cheriabi_gettimeofday_args *);
int	cheriabi_getrusage(struct thread *, struct cheriabi_getrusage_args *);
int	cheriabi_getsockopt(struct thread *, struct cheriabi_getsockopt_args *);
int	cheriabi_readv(struct thread *, struct cheriabi_readv_args *);
int	cheriabi_writev(struct thread *, struct cheriabi_writev_args *);
int	cheriabi_settimeofday(struct thread *, struct cheriabi_settimeofday_args *);
int	cheriabi_rename(struct thread *, struct cheriabi_rename_args *);
int	cheriabi_mkfifo(struct thread *, struct cheriabi_mkfifo_args *);
int	cheriabi_sendto(struct thread *, struct cheriabi_sendto_args *);
int	cheriabi_socketpair(struct thread *, struct cheriabi_socketpair_args *);
int	cheriabi_mkdir(struct thread *, struct cheriabi_mkdir_args *);
int	cheriabi_rmdir(struct thread *, struct cheriabi_rmdir_args *);
int	cheriabi_utimes(struct thread *, struct cheriabi_utimes_args *);
int	cheriabi_adjtime(struct thread *, struct cheriabi_adjtime_args *);
int	cheriabi_quotactl(struct thread *, struct cheriabi_quotactl_args *);
int	cheriabi_nlm_syscall(struct thread *, struct cheriabi_nlm_syscall_args *);
int	cheriabi_nfssvc(struct thread *, struct cheriabi_nfssvc_args *);
int	cheriabi_lgetfh(struct thread *, struct cheriabi_lgetfh_args *);
int	cheriabi_getfh(struct thread *, struct cheriabi_getfh_args *);
int	cheriabi_sysarch(struct thread *, struct cheriabi_sysarch_args *);
int	cheriabi_rtprio(struct thread *, struct cheriabi_rtprio_args *);
int	cheriabi_ntp_adjtime(struct thread *, struct cheriabi_ntp_adjtime_args *);
int	cheriabi_pathconf(struct thread *, struct cheriabi_pathconf_args *);
int	cheriabi_getrlimit(struct thread *, struct cheriabi___getrlimit_args *);
int	cheriabi_setrlimit(struct thread *, struct cheriabi___setrlimit_args *);
int	cheriabi___sysctl(struct thread *, struct cheriabi___sysctl_args *);
int	cheriabi_mlock(struct thread *, struct cheriabi_mlock_args *);
int	cheriabi_munlock(struct thread *, struct cheriabi_munlock_args *);
int	cheriabi_undelete(struct thread *, struct cheriabi_undelete_args *);
int	cheriabi_futimes(struct thread *, struct cheriabi_futimes_args *);
int	cheriabi_poll(struct thread *, struct cheriabi_poll_args *);
int	cheriabi_semop(struct thread *, struct cheriabi_semop_args *);
int	cheriabi_msgsnd(struct thread *, struct cheriabi_msgsnd_args *);
int	cheriabi_msgrcv(struct thread *, struct cheriabi_msgrcv_args *);
int	cheriabi_shmat(struct thread *, struct cheriabi_shmat_args *);
int	cheriabi_shmdt(struct thread *, struct cheriabi_shmdt_args *);
int	cheriabi_clock_gettime(struct thread *, struct cheriabi_clock_gettime_args *);
int	cheriabi_clock_settime(struct thread *, struct cheriabi_clock_settime_args *);
int	cheriabi_clock_getres(struct thread *, struct cheriabi_clock_getres_args *);
int	cheriabi_ktimer_create(struct thread *, struct cheriabi_ktimer_create_args *);
int	cheriabi_ktimer_settime(struct thread *, struct cheriabi_ktimer_settime_args *);
int	cheriabi_ktimer_gettime(struct thread *, struct cheriabi_ktimer_gettime_args *);
int	cheriabi_nanosleep(struct thread *, struct cheriabi_nanosleep_args *);
int	cheriabi_ffclock_getcounter(struct thread *, struct cheriabi_ffclock_getcounter_args *);
int	cheriabi_ffclock_setestimate(struct thread *, struct cheriabi_ffclock_setestimate_args *);
int	cheriabi_ffclock_getestimate(struct thread *, struct cheriabi_ffclock_getestimate_args *);
int	cheriabi_clock_nanosleep(struct thread *, struct cheriabi_clock_nanosleep_args *);
int	cheriabi_clock_getcpuclockid2(struct thread *, struct cheriabi_clock_getcpuclockid2_args *);
int	cheriabi_ntp_gettime(struct thread *, struct cheriabi_ntp_gettime_args *);
int	cheriabi_minherit(struct thread *, struct cheriabi_minherit_args *);
int	cheriabi_lchown(struct thread *, struct cheriabi_lchown_args *);
int	cheriabi_aio_read(struct thread *, struct cheriabi_aio_read_args *);
int	cheriabi_aio_write(struct thread *, struct cheriabi_aio_write_args *);
int	cheriabi_lio_listio(struct thread *, struct cheriabi_lio_listio_args *);
int	cheriabi_kbounce(struct thread *, struct cheriabi_kbounce_args *);
int	cheriabi_flag_captured(struct thread *, struct cheriabi_flag_captured_args *);
int	cheriabi_lchmod(struct thread *, struct cheriabi_lchmod_args *);
int	cheriabi_lutimes(struct thread *, struct cheriabi_lutimes_args *);
int	cheriabi_preadv(struct thread *, struct cheriabi_preadv_args *);
int	cheriabi_pwritev(struct thread *, struct cheriabi_pwritev_args *);
int	cheriabi_fhopen(struct thread *, struct cheriabi_fhopen_args *);
int	cheriabi_modstat(struct thread *, struct cheriabi_modstat_args *);
int	cheriabi_modfind(struct thread *, struct cheriabi_modfind_args *);
int	cheriabi_kldload(struct thread *, struct cheriabi_kldload_args *);
int	cheriabi_kldfind(struct thread *, struct cheriabi_kldfind_args *);
int	cheriabi_kldstat(struct thread *, struct cheriabi_kldstat_args *);
int	cheriabi_aio_return(struct thread *, struct cheriabi_aio_return_args *);
int	cheriabi_aio_suspend(struct thread *, struct cheriabi_aio_suspend_args *);
int	cheriabi_aio_cancel(struct thread *, struct cheriabi_aio_cancel_args *);
int	cheriabi_aio_error(struct thread *, struct cheriabi_aio_error_args *);
int	cheriabi___getcwd(struct thread *, struct cheriabi___getcwd_args *);
int	cheriabi_sched_setparam(struct thread *, struct cheriabi_sched_setparam_args *);
int	cheriabi_sched_getparam(struct thread *, struct cheriabi_sched_getparam_args *);
int	cheriabi_sched_setscheduler(struct thread *, struct cheriabi_sched_setscheduler_args *);
int	cheriabi_sched_rr_get_interval(struct thread *, struct cheriabi_sched_rr_get_interval_args *);
int	cheriabi_utrace(struct thread *, struct cheriabi_utrace_args *);
int	cheriabi_kldsym(struct thread *, struct cheriabi_kldsym_args *);
int	cheriabi_jail(struct thread *, struct cheriabi_jail_args *);
int	cheriabi_nnpfs_syscall(struct thread *, struct cheriabi_nnpfs_syscall_args *);
int	cheriabi_sigprocmask(struct thread *, struct cheriabi_sigprocmask_args *);
int	cheriabi_sigsuspend(struct thread *, struct cheriabi_sigsuspend_args *);
int	cheriabi_sigpending(struct thread *, struct cheriabi_sigpending_args *);
int	cheriabi_sigtimedwait(struct thread *, struct cheriabi_sigtimedwait_args *);
int	cheriabi_sigwaitinfo(struct thread *, struct cheriabi_sigwaitinfo_args *);
int	cheriabi___acl_get_file(struct thread *, struct cheriabi___acl_get_file_args *);
int	cheriabi___acl_set_file(struct thread *, struct cheriabi___acl_set_file_args *);
int	cheriabi___acl_get_fd(struct thread *, struct cheriabi___acl_get_fd_args *);
int	cheriabi___acl_set_fd(struct thread *, struct cheriabi___acl_set_fd_args *);
int	cheriabi___acl_delete_file(struct thread *, struct cheriabi___acl_delete_file_args *);
int	cheriabi___acl_aclcheck_file(struct thread *, struct cheriabi___acl_aclcheck_file_args *);
int	cheriabi___acl_aclcheck_fd(struct thread *, struct cheriabi___acl_aclcheck_fd_args *);
int	cheriabi_extattrctl(struct thread *, struct cheriabi_extattrctl_args *);
int	cheriabi_extattr_set_file(struct thread *, struct cheriabi_extattr_set_file_args *);
int	cheriabi_extattr_get_file(struct thread *, struct cheriabi_extattr_get_file_args *);
int	cheriabi_extattr_delete_file(struct thread *, struct cheriabi_extattr_delete_file_args *);
int	cheriabi_aio_waitcomplete(struct thread *, struct cheriabi_aio_waitcomplete_args *);
int	cheriabi_getresuid(struct thread *, struct cheriabi_getresuid_args *);
int	cheriabi_getresgid(struct thread *, struct cheriabi_getresgid_args *);
int	cheriabi_extattr_set_fd(struct thread *, struct cheriabi_extattr_set_fd_args *);
int	cheriabi_extattr_get_fd(struct thread *, struct cheriabi_extattr_get_fd_args *);
int	cheriabi_extattr_delete_fd(struct thread *, struct cheriabi_extattr_delete_fd_args *);
int	cheriabi_eaccess(struct thread *, struct cheriabi_eaccess_args *);
int	cheriabi_nmount(struct thread *, struct cheriabi_nmount_args *);
int	cheriabi___mac_get_proc(struct thread *, struct cheriabi___mac_get_proc_args *);
int	cheriabi___mac_set_proc(struct thread *, struct cheriabi___mac_set_proc_args *);
int	cheriabi___mac_get_fd(struct thread *, struct cheriabi___mac_get_fd_args *);
int	cheriabi___mac_get_file(struct thread *, struct cheriabi___mac_get_file_args *);
int	cheriabi___mac_set_fd(struct thread *, struct cheriabi___mac_set_fd_args *);
int	cheriabi___mac_set_file(struct thread *, struct cheriabi___mac_set_file_args *);
int	cheriabi_kenv(struct thread *, struct cheriabi_kenv_args *);
int	cheriabi_lchflags(struct thread *, struct cheriabi_lchflags_args *);
int	cheriabi_uuidgen(struct thread *, struct cheriabi_uuidgen_args *);
int	cheriabi_sendfile(struct thread *, struct cheriabi_sendfile_args *);
int	cheriabi_mac_syscall(struct thread *, struct cheriabi_mac_syscall_args *);
int	cheriabi_ksem_init(struct thread *, struct cheriabi_ksem_init_args *);
int	cheriabi_ksem_open(struct thread *, struct cheriabi_ksem_open_args *);
int	cheriabi_ksem_unlink(struct thread *, struct cheriabi_ksem_unlink_args *);
int	cheriabi_ksem_getvalue(struct thread *, struct cheriabi_ksem_getvalue_args *);
int	cheriabi___mac_get_pid(struct thread *, struct cheriabi___mac_get_pid_args *);
int	cheriabi___mac_get_link(struct thread *, struct cheriabi___mac_get_link_args *);
int	cheriabi___mac_set_link(struct thread *, struct cheriabi___mac_set_link_args *);
int	cheriabi_extattr_set_link(struct thread *, struct cheriabi_extattr_set_link_args *);
int	cheriabi_extattr_get_link(struct thread *, struct cheriabi_extattr_get_link_args *);
int	cheriabi_extattr_delete_link(struct thread *, struct cheriabi_extattr_delete_link_args *);
int	cheriabi___mac_execve(struct thread *, struct cheriabi___mac_execve_args *);
int	cheriabi_sigaction(struct thread *, struct cheriabi_sigaction_args *);
int	cheriabi_sigreturn(struct thread *, struct cheriabi_sigreturn_args *);
int	cheriabi_getcontext(struct thread *, struct cheriabi_getcontext_args *);
int	cheriabi_setcontext(struct thread *, struct cheriabi_setcontext_args *);
int	cheriabi_swapcontext(struct thread *, struct cheriabi_swapcontext_args *);
int	cheriabi_swapoff(struct thread *, struct cheriabi_swapoff_args *);
int	cheriabi___acl_get_link(struct thread *, struct cheriabi___acl_get_link_args *);
int	cheriabi___acl_set_link(struct thread *, struct cheriabi___acl_set_link_args *);
int	cheriabi___acl_delete_link(struct thread *, struct cheriabi___acl_delete_link_args *);
int	cheriabi___acl_aclcheck_link(struct thread *, struct cheriabi___acl_aclcheck_link_args *);
int	cheriabi_sigwait(struct thread *, struct cheriabi_sigwait_args *);
int	cheriabi_thr_create(struct thread *, struct cheriabi_thr_create_args *);
int	cheriabi_thr_exit(struct thread *, struct cheriabi_thr_exit_args *);
int	cheriabi_thr_self(struct thread *, struct cheriabi_thr_self_args *);
int	cheriabi_extattr_list_fd(struct thread *, struct cheriabi_extattr_list_fd_args *);
int	cheriabi_extattr_list_file(struct thread *, struct cheriabi_extattr_list_file_args *);
int	cheriabi_extattr_list_link(struct thread *, struct cheriabi_extattr_list_link_args *);
int	cheriabi_ksem_timedwait(struct thread *, struct cheriabi_ksem_timedwait_args *);
int	cheriabi_thr_suspend(struct thread *, struct cheriabi_thr_suspend_args *);
int	cheriabi_audit(struct thread *, struct cheriabi_audit_args *);
int	cheriabi_auditon(struct thread *, struct cheriabi_auditon_args *);
int	cheriabi_getauid(struct thread *, struct cheriabi_getauid_args *);
int	cheriabi_setauid(struct thread *, struct cheriabi_setauid_args *);
int	cheriabi_getaudit(struct thread *, struct cheriabi_getaudit_args *);
int	cheriabi_setaudit(struct thread *, struct cheriabi_setaudit_args *);
int	cheriabi_getaudit_addr(struct thread *, struct cheriabi_getaudit_addr_args *);
int	cheriabi_setaudit_addr(struct thread *, struct cheriabi_setaudit_addr_args *);
int	cheriabi_auditctl(struct thread *, struct cheriabi_auditctl_args *);
int	cheriabi__umtx_op(struct thread *, struct cheriabi__umtx_op_args *);
int	cheriabi_thr_new(struct thread *, struct cheriabi_thr_new_args *);
int	cheriabi_sigqueue(struct thread *, struct cheriabi_sigqueue_args *);
int	cheriabi_kmq_open(struct thread *, struct cheriabi_kmq_open_args *);
int	cheriabi_kmq_setattr(struct thread *, struct cheriabi_kmq_setattr_args *);
int	cheriabi_kmq_timedreceive(struct thread *, struct cheriabi_kmq_timedreceive_args *);
int	cheriabi_kmq_timedsend(struct thread *, struct cheriabi_kmq_timedsend_args *);
int	cheriabi_kmq_notify(struct thread *, struct cheriabi_kmq_notify_args *);
int	cheriabi_kmq_unlink(struct thread *, struct cheriabi_kmq_unlink_args *);
int	cheriabi_abort2(struct thread *, struct cheriabi_abort2_args *);
int	cheriabi_thr_set_name(struct thread *, struct cheriabi_thr_set_name_args *);
int	cheriabi_aio_fsync(struct thread *, struct cheriabi_aio_fsync_args *);
int	cheriabi_rtprio_thread(struct thread *, struct cheriabi_rtprio_thread_args *);
int	cheriabi_sctp_generic_sendmsg(struct thread *, struct cheriabi_sctp_generic_sendmsg_args *);
int	cheriabi_sctp_generic_sendmsg_iov(struct thread *, struct cheriabi_sctp_generic_sendmsg_iov_args *);
int	cheriabi_sctp_generic_recvmsg(struct thread *, struct cheriabi_sctp_generic_recvmsg_args *);
int	cheriabi_pread(struct thread *, struct cheriabi_pread_args *);
int	cheriabi_pwrite(struct thread *, struct cheriabi_pwrite_args *);
int	cheriabi_mmap(struct thread *, struct cheriabi_mmap_args *);
int	cheriabi_truncate(struct thread *, struct cheriabi_truncate_args *);
int	cheriabi_shm_unlink(struct thread *, struct cheriabi_shm_unlink_args *);
int	cheriabi_cpuset(struct thread *, struct cheriabi_cpuset_args *);
int	cheriabi_cpuset_getid(struct thread *, struct cheriabi_cpuset_getid_args *);
int	cheriabi_cpuset_getaffinity(struct thread *, struct cheriabi_cpuset_getaffinity_args *);
int	cheriabi_cpuset_setaffinity(struct thread *, struct cheriabi_cpuset_setaffinity_args *);
int	cheriabi_faccessat(struct thread *, struct cheriabi_faccessat_args *);
int	cheriabi_fchmodat(struct thread *, struct cheriabi_fchmodat_args *);
int	cheriabi_fchownat(struct thread *, struct cheriabi_fchownat_args *);
int	cheriabi_fexecve(struct thread *, struct cheriabi_fexecve_args *);
int	cheriabi_futimesat(struct thread *, struct cheriabi_futimesat_args *);
int	cheriabi_linkat(struct thread *, struct cheriabi_linkat_args *);
int	cheriabi_mkdirat(struct thread *, struct cheriabi_mkdirat_args *);
int	cheriabi_mkfifoat(struct thread *, struct cheriabi_mkfifoat_args *);
int	cheriabi_openat(struct thread *, struct cheriabi_openat_args *);
int	cheriabi_readlinkat(struct thread *, struct cheriabi_readlinkat_args *);
int	cheriabi_renameat(struct thread *, struct cheriabi_renameat_args *);
int	cheriabi_symlinkat(struct thread *, struct cheriabi_symlinkat_args *);
int	cheriabi_unlinkat(struct thread *, struct cheriabi_unlinkat_args *);
int	cheriabi_gssd_syscall(struct thread *, struct cheriabi_gssd_syscall_args *);
int	cheriabi_jail_get(struct thread *, struct cheriabi_jail_get_args *);
int	cheriabi_jail_set(struct thread *, struct cheriabi_jail_set_args *);
int	cheriabi___semctl(struct thread *, struct cheriabi___semctl_args *);
int	cheriabi_msgctl(struct thread *, struct cheriabi_msgctl_args *);
int	cheriabi_shmctl(struct thread *, struct cheriabi_shmctl_args *);
int	cheriabi_lpathconf(struct thread *, struct cheriabi_lpathconf_args *);
int	cheriabi___cap_rights_get(struct thread *, struct cheriabi___cap_rights_get_args *);
int	cheriabi_cap_getmode(struct thread *, struct cheriabi_cap_getmode_args *);
int	cheriabi_pdfork(struct thread *, struct cheriabi_pdfork_args *);
int	cheriabi_pdgetpid(struct thread *, struct cheriabi_pdgetpid_args *);
int	cheriabi_pselect(struct thread *, struct cheriabi_pselect_args *);
int	cheriabi_getloginclass(struct thread *, struct cheriabi_getloginclass_args *);
int	cheriabi_setloginclass(struct thread *, struct cheriabi_setloginclass_args *);
int	cheriabi_rctl_get_racct(struct thread *, struct cheriabi_rctl_get_racct_args *);
int	cheriabi_rctl_get_rules(struct thread *, struct cheriabi_rctl_get_rules_args *);
int	cheriabi_rctl_get_limits(struct thread *, struct cheriabi_rctl_get_limits_args *);
int	cheriabi_rctl_add_rule(struct thread *, struct cheriabi_rctl_add_rule_args *);
int	cheriabi_rctl_remove_rule(struct thread *, struct cheriabi_rctl_remove_rule_args *);
int	cheriabi_wait6(struct thread *, struct cheriabi_wait6_args *);
int	cheriabi_cap_rights_limit(struct thread *, struct cheriabi_cap_rights_limit_args *);
int	cheriabi_cap_ioctls_limit(struct thread *, struct cheriabi_cap_ioctls_limit_args *);
int	cheriabi_cap_ioctls_get(struct thread *, struct cheriabi_cap_ioctls_get_args *);
int	cheriabi_cap_fcntls_get(struct thread *, struct cheriabi_cap_fcntls_get_args *);
int	cheriabi_bindat(struct thread *, struct cheriabi_bindat_args *);
int	cheriabi_connectat(struct thread *, struct cheriabi_connectat_args *);
int	cheriabi_chflagsat(struct thread *, struct cheriabi_chflagsat_args *);
int	cheriabi_accept4(struct thread *, struct cheriabi_accept4_args *);
int	cheriabi_pipe2(struct thread *, struct cheriabi_pipe2_args *);
int	cheriabi_aio_mlock(struct thread *, struct cheriabi_aio_mlock_args *);
int	cheriabi_procctl(struct thread *, struct cheriabi_procctl_args *);
int	cheriabi_ppoll(struct thread *, struct cheriabi_ppoll_args *);
int	cheriabi_futimens(struct thread *, struct cheriabi_futimens_args *);
int	cheriabi_utimensat(struct thread *, struct cheriabi_utimensat_args *);
int	cheriabi_fstat(struct thread *, struct cheriabi_fstat_args *);
int	cheriabi_fstatat(struct thread *, struct cheriabi_fstatat_args *);
int	cheriabi_fhstat(struct thread *, struct cheriabi_fhstat_args *);
int	cheriabi_getdirentries(struct thread *, struct cheriabi_getdirentries_args *);
int	cheriabi_statfs(struct thread *, struct cheriabi_statfs_args *);
int	cheriabi_fstatfs(struct thread *, struct cheriabi_fstatfs_args *);
int	cheriabi_getfsstat(struct thread *, struct cheriabi_getfsstat_args *);
int	cheriabi_fhstatfs(struct thread *, struct cheriabi_fhstatfs_args *);
int	cheriabi_mknodat(struct thread *, struct cheriabi_mknodat_args *);
int	cheriabi_kevent(struct thread *, struct cheriabi_kevent_args *);
int	cheriabi_cpuset_getdomain(struct thread *, struct cheriabi_cpuset_getdomain_args *);
int	cheriabi_cpuset_setdomain(struct thread *, struct cheriabi_cpuset_setdomain_args *);
int	cheriabi_getrandom(struct thread *, struct cheriabi_getrandom_args *);
int	cheriabi_getfhat(struct thread *, struct cheriabi_getfhat_args *);
int	cheriabi_fhlink(struct thread *, struct cheriabi_fhlink_args *);
int	cheriabi_fhlinkat(struct thread *, struct cheriabi_fhlinkat_args *);
int	cheriabi_fhreadlink(struct thread *, struct cheriabi_fhreadlink_args *);
int	cheriabi_funlinkat(struct thread *, struct cheriabi_funlinkat_args *);
int	cheriabi_copy_file_range(struct thread *, struct cheriabi_copy_file_range_args *);
int	cheriabi___sysctlbyname(struct thread *, struct cheriabi___sysctlbyname_args *);
int	cheriabi_shm_open2(struct thread *, struct cheriabi_shm_open2_args *);
int	cheriabi_shm_rename(struct thread *, struct cheriabi_shm_rename_args *);
int	cheriabi_sigfastblock(struct thread *, struct cheriabi_sigfastblock_args *);
int	cheriabi___realpathat(struct thread *, struct cheriabi___realpathat_args *);
int	cheriabi_rpctls_syscall(struct thread *, struct cheriabi_rpctls_syscall_args *);

#ifdef COMPAT_43


#endif /* COMPAT_43 */


#ifdef COMPAT_FREEBSD4


#endif /* COMPAT_FREEBSD4 */


#ifdef COMPAT_FREEBSD6


#endif /* COMPAT_FREEBSD6 */


#ifdef COMPAT_FREEBSD7


#endif /* COMPAT_FREEBSD7 */


#ifdef COMPAT_FREEBSD10


#endif /* COMPAT_FREEBSD10 */


#ifdef COMPAT_FREEBSD11


#endif /* COMPAT_FREEBSD11 */


#ifdef COMPAT_FREEBSD12

struct freebsd12_cheriabi_shm_open_args {
	char path_l_[PADL_(const char * __capability)]; const char * __capability path; char path_r_[PADR_(const char * __capability)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
	char mode_l_[PADL_(mode_t)]; mode_t mode; char mode_r_[PADR_(mode_t)];
};
int	freebsd12_cheriabi_shm_open(struct thread *, struct freebsd12_cheriabi_shm_open_args *);

#endif /* COMPAT_FREEBSD12 */

#define	CHERIABI_SYS_AUE_cheriabi_read	AUE_READ
#define	CHERIABI_SYS_AUE_cheriabi_write	AUE_WRITE
#define	CHERIABI_SYS_AUE_cheriabi_open	AUE_OPEN_RWTC
#define	CHERIABI_SYS_AUE_cheriabi_wait4	AUE_WAIT4
#define	CHERIABI_SYS_AUE_cheriabi_link	AUE_LINK
#define	CHERIABI_SYS_AUE_cheriabi_unlink	AUE_UNLINK
#define	CHERIABI_SYS_AUE_cheriabi_chdir	AUE_CHDIR
#define	CHERIABI_SYS_AUE_cheriabi_chmod	AUE_CHMOD
#define	CHERIABI_SYS_AUE_cheriabi_chown	AUE_CHOWN
#define	CHERIABI_SYS_AUE_cheriabi_mount	AUE_MOUNT
#define	CHERIABI_SYS_AUE_cheriabi_unmount	AUE_UMOUNT
#define	CHERIABI_SYS_AUE_cheriabi_ptrace	AUE_PTRACE
#define	CHERIABI_SYS_AUE_cheriabi_recvmsg	AUE_RECVMSG
#define	CHERIABI_SYS_AUE_cheriabi_sendmsg	AUE_SENDMSG
#define	CHERIABI_SYS_AUE_cheriabi_recvfrom	AUE_RECVFROM
#define	CHERIABI_SYS_AUE_cheriabi_accept	AUE_ACCEPT
#define	CHERIABI_SYS_AUE_cheriabi_getpeername	AUE_GETPEERNAME
#define	CHERIABI_SYS_AUE_cheriabi_getsockname	AUE_GETSOCKNAME
#define	CHERIABI_SYS_AUE_cheriabi_access	AUE_ACCESS
#define	CHERIABI_SYS_AUE_cheriabi_chflags	AUE_CHFLAGS
#define	CHERIABI_SYS_AUE_cheriabi_profil	AUE_PROFILE
#define	CHERIABI_SYS_AUE_cheriabi_ktrace	AUE_KTRACE
#define	CHERIABI_SYS_AUE_cheriabi_getlogin	AUE_GETLOGIN
#define	CHERIABI_SYS_AUE_cheriabi_setlogin	AUE_SETLOGIN
#define	CHERIABI_SYS_AUE_cheriabi_acct	AUE_ACCT
#define	CHERIABI_SYS_AUE_cheriabi_sigaltstack	AUE_SIGALTSTACK
#define	CHERIABI_SYS_AUE_cheriabi_ioctl	AUE_IOCTL
#define	CHERIABI_SYS_AUE_cheriabi_revoke	AUE_REVOKE
#define	CHERIABI_SYS_AUE_cheriabi_symlink	AUE_SYMLINK
#define	CHERIABI_SYS_AUE_cheriabi_readlink	AUE_READLINK
#define	CHERIABI_SYS_AUE_cheriabi_execve	AUE_EXECVE
#define	CHERIABI_SYS_AUE_cheriabi_chroot	AUE_CHROOT
#define	CHERIABI_SYS_AUE_cheriabi_msync	AUE_MSYNC
#define	CHERIABI_SYS_AUE_cheriabi_munmap	AUE_MUNMAP
#define	CHERIABI_SYS_AUE_cheriabi_mprotect	AUE_MPROTECT
#define	CHERIABI_SYS_AUE_cheriabi_madvise	AUE_MADVISE
#define	CHERIABI_SYS_AUE_cheriabi_mincore	AUE_MINCORE
#define	CHERIABI_SYS_AUE_cheriabi_getgroups	AUE_GETGROUPS
#define	CHERIABI_SYS_AUE_cheriabi_setgroups	AUE_SETGROUPS
#define	CHERIABI_SYS_AUE_cheriabi_setitimer	AUE_SETITIMER
#define	CHERIABI_SYS_AUE_cheriabi_swapon	AUE_SWAPON
#define	CHERIABI_SYS_AUE_cheriabi_getitimer	AUE_GETITIMER
#define	CHERIABI_SYS_AUE_cheriabi_fcntl	AUE_FCNTL
#define	CHERIABI_SYS_AUE_cheriabi_select	AUE_SELECT
#define	CHERIABI_SYS_AUE_cheriabi_connect	AUE_CONNECT
#define	CHERIABI_SYS_AUE_cheriabi_bind	AUE_BIND
#define	CHERIABI_SYS_AUE_cheriabi_setsockopt	AUE_SETSOCKOPT
#define	CHERIABI_SYS_AUE_cheriabi_gettimeofday	AUE_GETTIMEOFDAY
#define	CHERIABI_SYS_AUE_cheriabi_getrusage	AUE_GETRUSAGE
#define	CHERIABI_SYS_AUE_cheriabi_getsockopt	AUE_GETSOCKOPT
#define	CHERIABI_SYS_AUE_cheriabi_readv	AUE_READV
#define	CHERIABI_SYS_AUE_cheriabi_writev	AUE_WRITEV
#define	CHERIABI_SYS_AUE_cheriabi_settimeofday	AUE_SETTIMEOFDAY
#define	CHERIABI_SYS_AUE_cheriabi_rename	AUE_RENAME
#define	CHERIABI_SYS_AUE_cheriabi_mkfifo	AUE_MKFIFO
#define	CHERIABI_SYS_AUE_cheriabi_sendto	AUE_SENDTO
#define	CHERIABI_SYS_AUE_cheriabi_socketpair	AUE_SOCKETPAIR
#define	CHERIABI_SYS_AUE_cheriabi_mkdir	AUE_MKDIR
#define	CHERIABI_SYS_AUE_cheriabi_rmdir	AUE_RMDIR
#define	CHERIABI_SYS_AUE_cheriabi_utimes	AUE_UTIMES
#define	CHERIABI_SYS_AUE_cheriabi_adjtime	AUE_ADJTIME
#define	CHERIABI_SYS_AUE_cheriabi_quotactl	AUE_QUOTACTL
#define	CHERIABI_SYS_AUE_cheriabi_nlm_syscall	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_nfssvc	AUE_NFS_SVC
#define	CHERIABI_SYS_AUE_cheriabi_lgetfh	AUE_LGETFH
#define	CHERIABI_SYS_AUE_cheriabi_getfh	AUE_NFS_GETFH
#define	CHERIABI_SYS_AUE_cheriabi_sysarch	AUE_SYSARCH
#define	CHERIABI_SYS_AUE_cheriabi_rtprio	AUE_RTPRIO
#define	CHERIABI_SYS_AUE_cheriabi_ntp_adjtime	AUE_NTP_ADJTIME
#define	CHERIABI_SYS_AUE_cheriabi_pathconf	AUE_PATHCONF
#define	CHERIABI_SYS_AUE_getrlimit	AUE_GETRLIMIT
#define	CHERIABI_SYS_AUE_setrlimit	AUE_SETRLIMIT
#define	CHERIABI_SYS_AUE_cheriabi___sysctl	AUE_SYSCTL
#define	CHERIABI_SYS_AUE_cheriabi_mlock	AUE_MLOCK
#define	CHERIABI_SYS_AUE_cheriabi_munlock	AUE_MUNLOCK
#define	CHERIABI_SYS_AUE_cheriabi_undelete	AUE_UNDELETE
#define	CHERIABI_SYS_AUE_cheriabi_futimes	AUE_FUTIMES
#define	CHERIABI_SYS_AUE_cheriabi_poll	AUE_POLL
#define	CHERIABI_SYS_AUE_cheriabi_semop	AUE_SEMOP
#define	CHERIABI_SYS_AUE_cheriabi_msgsnd	AUE_MSGSND
#define	CHERIABI_SYS_AUE_cheriabi_msgrcv	AUE_MSGRCV
#define	CHERIABI_SYS_AUE_cheriabi_shmat	AUE_SHMAT
#define	CHERIABI_SYS_AUE_cheriabi_shmdt	AUE_SHMDT
#define	CHERIABI_SYS_AUE_cheriabi_clock_gettime	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_clock_settime	AUE_CLOCK_SETTIME
#define	CHERIABI_SYS_AUE_cheriabi_clock_getres	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_ktimer_create	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_ktimer_settime	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_ktimer_gettime	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_nanosleep	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_ffclock_getcounter	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_ffclock_setestimate	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_ffclock_getestimate	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_clock_nanosleep	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_clock_getcpuclockid2	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_ntp_gettime	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_minherit	AUE_MINHERIT
#define	CHERIABI_SYS_AUE_cheriabi_lchown	AUE_LCHOWN
#define	CHERIABI_SYS_AUE_cheriabi_aio_read	AUE_AIO_READ
#define	CHERIABI_SYS_AUE_cheriabi_aio_write	AUE_AIO_WRITE
#define	CHERIABI_SYS_AUE_cheriabi_lio_listio	AUE_LIO_LISTIO
#define	CHERIABI_SYS_AUE_cheriabi_kbounce	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_flag_captured	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_lchmod	AUE_LCHMOD
#define	CHERIABI_SYS_AUE_cheriabi_lutimes	AUE_LUTIMES
#define	CHERIABI_SYS_AUE_cheriabi_preadv	AUE_PREADV
#define	CHERIABI_SYS_AUE_cheriabi_pwritev	AUE_PWRITEV
#define	CHERIABI_SYS_AUE_cheriabi_fhopen	AUE_FHOPEN
#define	CHERIABI_SYS_AUE_cheriabi_modstat	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_modfind	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_kldload	AUE_MODLOAD
#define	CHERIABI_SYS_AUE_cheriabi_kldfind	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_kldstat	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_return	AUE_AIO_RETURN
#define	CHERIABI_SYS_AUE_cheriabi_aio_suspend	AUE_AIO_SUSPEND
#define	CHERIABI_SYS_AUE_cheriabi_aio_cancel	AUE_AIO_CANCEL
#define	CHERIABI_SYS_AUE_cheriabi_aio_error	AUE_AIO_ERROR
#define	CHERIABI_SYS_AUE_cheriabi___getcwd	AUE_GETCWD
#define	CHERIABI_SYS_AUE_cheriabi_sched_setparam	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_sched_getparam	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_sched_setscheduler	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_sched_rr_get_interval	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_utrace	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_kldsym	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_jail	AUE_JAIL
#define	CHERIABI_SYS_AUE_cheriabi_nnpfs_syscall	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_sigprocmask	AUE_SIGPROCMASK
#define	CHERIABI_SYS_AUE_cheriabi_sigsuspend	AUE_SIGSUSPEND
#define	CHERIABI_SYS_AUE_cheriabi_sigpending	AUE_SIGPENDING
#define	CHERIABI_SYS_AUE_cheriabi_sigtimedwait	AUE_SIGWAIT
#define	CHERIABI_SYS_AUE_cheriabi_sigwaitinfo	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___acl_get_file	AUE_ACL_GET_FILE
#define	CHERIABI_SYS_AUE_cheriabi___acl_set_file	AUE_ACL_SET_FILE
#define	CHERIABI_SYS_AUE_cheriabi___acl_get_fd	AUE_ACL_GET_FD
#define	CHERIABI_SYS_AUE_cheriabi___acl_set_fd	AUE_ACL_SET_FD
#define	CHERIABI_SYS_AUE_cheriabi___acl_delete_file	AUE_ACL_DELETE_FILE
#define	CHERIABI_SYS_AUE_cheriabi___acl_aclcheck_file	AUE_ACL_CHECK_FILE
#define	CHERIABI_SYS_AUE_cheriabi___acl_aclcheck_fd	AUE_ACL_CHECK_FD
#define	CHERIABI_SYS_AUE_cheriabi_extattrctl	AUE_EXTATTRCTL
#define	CHERIABI_SYS_AUE_cheriabi_extattr_set_file	AUE_EXTATTR_SET_FILE
#define	CHERIABI_SYS_AUE_cheriabi_extattr_get_file	AUE_EXTATTR_GET_FILE
#define	CHERIABI_SYS_AUE_cheriabi_extattr_delete_file	AUE_EXTATTR_DELETE_FILE
#define	CHERIABI_SYS_AUE_cheriabi_aio_waitcomplete	AUE_AIO_WAITCOMPLETE
#define	CHERIABI_SYS_AUE_cheriabi_getresuid	AUE_GETRESUID
#define	CHERIABI_SYS_AUE_cheriabi_getresgid	AUE_GETRESGID
#define	CHERIABI_SYS_AUE_cheriabi_extattr_set_fd	AUE_EXTATTR_SET_FD
#define	CHERIABI_SYS_AUE_cheriabi_extattr_get_fd	AUE_EXTATTR_GET_FD
#define	CHERIABI_SYS_AUE_cheriabi_extattr_delete_fd	AUE_EXTATTR_DELETE_FD
#define	CHERIABI_SYS_AUE_cheriabi_eaccess	AUE_EACCESS
#define	CHERIABI_SYS_AUE_cheriabi_nmount	AUE_NMOUNT
#define	CHERIABI_SYS_AUE_cheriabi___mac_get_proc	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___mac_set_proc	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___mac_get_fd	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___mac_get_file	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___mac_set_fd	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___mac_set_file	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_kenv	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_lchflags	AUE_LCHFLAGS
#define	CHERIABI_SYS_AUE_cheriabi_uuidgen	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_sendfile	AUE_SENDFILE
#define	CHERIABI_SYS_AUE_cheriabi_mac_syscall	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_ksem_init	AUE_SEMINIT
#define	CHERIABI_SYS_AUE_cheriabi_ksem_open	AUE_SEMOPEN
#define	CHERIABI_SYS_AUE_cheriabi_ksem_unlink	AUE_SEMUNLINK
#define	CHERIABI_SYS_AUE_cheriabi_ksem_getvalue	AUE_SEMGETVALUE
#define	CHERIABI_SYS_AUE_cheriabi___mac_get_pid	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___mac_get_link	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___mac_set_link	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_extattr_set_link	AUE_EXTATTR_SET_LINK
#define	CHERIABI_SYS_AUE_cheriabi_extattr_get_link	AUE_EXTATTR_GET_LINK
#define	CHERIABI_SYS_AUE_cheriabi_extattr_delete_link	AUE_EXTATTR_DELETE_LINK
#define	CHERIABI_SYS_AUE_cheriabi___mac_execve	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_sigaction	AUE_SIGACTION
#define	CHERIABI_SYS_AUE_cheriabi_sigreturn	AUE_SIGRETURN
#define	CHERIABI_SYS_AUE_cheriabi_getcontext	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_setcontext	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_swapcontext	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_swapoff	AUE_SWAPOFF
#define	CHERIABI_SYS_AUE_cheriabi___acl_get_link	AUE_ACL_GET_LINK
#define	CHERIABI_SYS_AUE_cheriabi___acl_set_link	AUE_ACL_SET_LINK
#define	CHERIABI_SYS_AUE_cheriabi___acl_delete_link	AUE_ACL_DELETE_LINK
#define	CHERIABI_SYS_AUE_cheriabi___acl_aclcheck_link	AUE_ACL_CHECK_LINK
#define	CHERIABI_SYS_AUE_cheriabi_sigwait	AUE_SIGWAIT
#define	CHERIABI_SYS_AUE_cheriabi_thr_create	AUE_THR_CREATE
#define	CHERIABI_SYS_AUE_cheriabi_thr_exit	AUE_THR_EXIT
#define	CHERIABI_SYS_AUE_cheriabi_thr_self	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_extattr_list_fd	AUE_EXTATTR_LIST_FD
#define	CHERIABI_SYS_AUE_cheriabi_extattr_list_file	AUE_EXTATTR_LIST_FILE
#define	CHERIABI_SYS_AUE_cheriabi_extattr_list_link	AUE_EXTATTR_LIST_LINK
#define	CHERIABI_SYS_AUE_cheriabi_ksem_timedwait	AUE_SEMWAIT
#define	CHERIABI_SYS_AUE_cheriabi_thr_suspend	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_audit	AUE_AUDIT
#define	CHERIABI_SYS_AUE_cheriabi_auditon	AUE_AUDITON
#define	CHERIABI_SYS_AUE_cheriabi_getauid	AUE_GETAUID
#define	CHERIABI_SYS_AUE_cheriabi_setauid	AUE_SETAUID
#define	CHERIABI_SYS_AUE_cheriabi_getaudit	AUE_GETAUDIT
#define	CHERIABI_SYS_AUE_cheriabi_setaudit	AUE_SETAUDIT
#define	CHERIABI_SYS_AUE_cheriabi_getaudit_addr	AUE_GETAUDIT_ADDR
#define	CHERIABI_SYS_AUE_cheriabi_setaudit_addr	AUE_SETAUDIT_ADDR
#define	CHERIABI_SYS_AUE_cheriabi_auditctl	AUE_AUDITCTL
#define	CHERIABI_SYS_AUE_cheriabi__umtx_op	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_thr_new	AUE_THR_NEW
#define	CHERIABI_SYS_AUE_cheriabi_sigqueue	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_kmq_open	AUE_MQ_OPEN
#define	CHERIABI_SYS_AUE_cheriabi_kmq_setattr	AUE_MQ_SETATTR
#define	CHERIABI_SYS_AUE_cheriabi_kmq_timedreceive	AUE_MQ_TIMEDRECEIVE
#define	CHERIABI_SYS_AUE_cheriabi_kmq_timedsend	AUE_MQ_TIMEDSEND
#define	CHERIABI_SYS_AUE_cheriabi_kmq_notify	AUE_MQ_NOTIFY
#define	CHERIABI_SYS_AUE_cheriabi_kmq_unlink	AUE_MQ_UNLINK
#define	CHERIABI_SYS_AUE_cheriabi_abort2	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_thr_set_name	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_fsync	AUE_AIO_FSYNC
#define	CHERIABI_SYS_AUE_cheriabi_rtprio_thread	AUE_RTPRIO
#define	CHERIABI_SYS_AUE_cheriabi_sctp_generic_sendmsg	AUE_SCTP_GENERIC_SENDMSG
#define	CHERIABI_SYS_AUE_cheriabi_sctp_generic_sendmsg_iov	AUE_SCTP_GENERIC_SENDMSG_IOV
#define	CHERIABI_SYS_AUE_cheriabi_sctp_generic_recvmsg	AUE_SCTP_GENERIC_RECVMSG
#define	CHERIABI_SYS_AUE_cheriabi_pread	AUE_PREAD
#define	CHERIABI_SYS_AUE_cheriabi_pwrite	AUE_PWRITE
#define	CHERIABI_SYS_AUE_cheriabi_mmap	AUE_MMAP
#define	CHERIABI_SYS_AUE_cheriabi_truncate	AUE_TRUNCATE
#define	CHERIABI_SYS_AUE_freebsd12_cheriabi_shm_open	AUE_SHMOPEN
#define	CHERIABI_SYS_AUE_cheriabi_shm_unlink	AUE_SHMUNLINK
#define	CHERIABI_SYS_AUE_cheriabi_cpuset	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_cpuset_getid	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_cpuset_getaffinity	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_cpuset_setaffinity	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_faccessat	AUE_FACCESSAT
#define	CHERIABI_SYS_AUE_cheriabi_fchmodat	AUE_FCHMODAT
#define	CHERIABI_SYS_AUE_cheriabi_fchownat	AUE_FCHOWNAT
#define	CHERIABI_SYS_AUE_cheriabi_fexecve	AUE_FEXECVE
#define	CHERIABI_SYS_AUE_cheriabi_futimesat	AUE_FUTIMESAT
#define	CHERIABI_SYS_AUE_cheriabi_linkat	AUE_LINKAT
#define	CHERIABI_SYS_AUE_cheriabi_mkdirat	AUE_MKDIRAT
#define	CHERIABI_SYS_AUE_cheriabi_mkfifoat	AUE_MKFIFOAT
#define	CHERIABI_SYS_AUE_cheriabi_openat	AUE_OPENAT_RWTC
#define	CHERIABI_SYS_AUE_cheriabi_readlinkat	AUE_READLINKAT
#define	CHERIABI_SYS_AUE_cheriabi_renameat	AUE_RENAMEAT
#define	CHERIABI_SYS_AUE_cheriabi_symlinkat	AUE_SYMLINKAT
#define	CHERIABI_SYS_AUE_cheriabi_unlinkat	AUE_UNLINKAT
#define	CHERIABI_SYS_AUE_cheriabi_gssd_syscall	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_jail_get	AUE_JAIL_GET
#define	CHERIABI_SYS_AUE_cheriabi_jail_set	AUE_JAIL_SET
#define	CHERIABI_SYS_AUE_cheriabi___semctl	AUE_SEMCTL
#define	CHERIABI_SYS_AUE_cheriabi_msgctl	AUE_MSGCTL
#define	CHERIABI_SYS_AUE_cheriabi_shmctl	AUE_SHMCTL
#define	CHERIABI_SYS_AUE_cheriabi_lpathconf	AUE_LPATHCONF
#define	CHERIABI_SYS_AUE_cheriabi___cap_rights_get	AUE_CAP_RIGHTS_GET
#define	CHERIABI_SYS_AUE_cheriabi_cap_getmode	AUE_CAP_GETMODE
#define	CHERIABI_SYS_AUE_cheriabi_pdfork	AUE_PDFORK
#define	CHERIABI_SYS_AUE_cheriabi_pdgetpid	AUE_PDGETPID
#define	CHERIABI_SYS_AUE_cheriabi_pselect	AUE_SELECT
#define	CHERIABI_SYS_AUE_cheriabi_getloginclass	AUE_GETLOGINCLASS
#define	CHERIABI_SYS_AUE_cheriabi_setloginclass	AUE_SETLOGINCLASS
#define	CHERIABI_SYS_AUE_cheriabi_rctl_get_racct	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_rctl_get_rules	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_rctl_get_limits	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_rctl_add_rule	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_rctl_remove_rule	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_wait6	AUE_WAIT6
#define	CHERIABI_SYS_AUE_cheriabi_cap_rights_limit	AUE_CAP_RIGHTS_LIMIT
#define	CHERIABI_SYS_AUE_cheriabi_cap_ioctls_limit	AUE_CAP_IOCTLS_LIMIT
#define	CHERIABI_SYS_AUE_cheriabi_cap_ioctls_get	AUE_CAP_IOCTLS_GET
#define	CHERIABI_SYS_AUE_cheriabi_cap_fcntls_get	AUE_CAP_FCNTLS_GET
#define	CHERIABI_SYS_AUE_cheriabi_bindat	AUE_BINDAT
#define	CHERIABI_SYS_AUE_cheriabi_connectat	AUE_CONNECTAT
#define	CHERIABI_SYS_AUE_cheriabi_chflagsat	AUE_CHFLAGSAT
#define	CHERIABI_SYS_AUE_cheriabi_accept4	AUE_ACCEPT
#define	CHERIABI_SYS_AUE_cheriabi_pipe2	AUE_PIPE
#define	CHERIABI_SYS_AUE_cheriabi_aio_mlock	AUE_AIO_MLOCK
#define	CHERIABI_SYS_AUE_cheriabi_procctl	AUE_PROCCTL
#define	CHERIABI_SYS_AUE_cheriabi_ppoll	AUE_POLL
#define	CHERIABI_SYS_AUE_cheriabi_futimens	AUE_FUTIMES
#define	CHERIABI_SYS_AUE_cheriabi_utimensat	AUE_FUTIMESAT
#define	CHERIABI_SYS_AUE_cheriabi_fstat	AUE_FSTAT
#define	CHERIABI_SYS_AUE_cheriabi_fstatat	AUE_FSTATAT
#define	CHERIABI_SYS_AUE_cheriabi_fhstat	AUE_FHSTAT
#define	CHERIABI_SYS_AUE_cheriabi_getdirentries	AUE_GETDIRENTRIES
#define	CHERIABI_SYS_AUE_cheriabi_statfs	AUE_STATFS
#define	CHERIABI_SYS_AUE_cheriabi_fstatfs	AUE_FSTATFS
#define	CHERIABI_SYS_AUE_cheriabi_getfsstat	AUE_GETFSSTAT
#define	CHERIABI_SYS_AUE_cheriabi_fhstatfs	AUE_FHSTATFS
#define	CHERIABI_SYS_AUE_cheriabi_mknodat	AUE_MKNODAT
#define	CHERIABI_SYS_AUE_cheriabi_kevent	AUE_KEVENT
#define	CHERIABI_SYS_AUE_cheriabi_cpuset_getdomain	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_cpuset_setdomain	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_getrandom	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_getfhat	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_fhlink	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_fhlinkat	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_fhreadlink	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_funlinkat	AUE_UNLINKAT
#define	CHERIABI_SYS_AUE_cheriabi_copy_file_range	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___sysctlbyname	AUE_SYSCTL
#define	CHERIABI_SYS_AUE_cheriabi_shm_open2	AUE_SHMOPEN
#define	CHERIABI_SYS_AUE_cheriabi_shm_rename	AUE_SHMRENAME
#define	CHERIABI_SYS_AUE_cheriabi_sigfastblock	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi___realpathat	AUE_REALPATHAT
#define	CHERIABI_SYS_AUE_cheriabi_rpctls_syscall	AUE_NULL

#undef PAD_
#undef PADL_
#undef PADR_

#endif /* !_CHERIABI_PROTO_H_ */
