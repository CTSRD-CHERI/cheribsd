/*
 * System call prototypes.
 *
 * DO NOT EDIT-- this file is automatically @generated.
 * $FreeBSD$
 */

#ifndef _FREEBSD32_SYSPROTO_H_
#define	_FREEBSD32_SYSPROTO_H_

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
#else
#define	PADL_(t)	PAD_(t)
#define	PADR_(t)	0
#endif

#if !defined(PAD64_REQUIRED) && !defined(__amd64__)
#define PAD64_REQUIRED
#endif
struct freebsd32_sigaltstack_args {
	char ss_l_[PADL_(const struct sigaltstack32 *)]; const struct sigaltstack32 * ss; char ss_r_[PADR_(const struct sigaltstack32 *)];
	char oss_l_[PADL_(struct sigaltstack32 *)]; struct sigaltstack32 * oss; char oss_r_[PADR_(struct sigaltstack32 *)];
};
struct freebsd32_execve_args {
	char fname_l_[PADL_(const char *)]; const char * fname; char fname_r_[PADR_(const char *)];
	char argv_l_[PADL_(uint32_t *)]; uint32_t * argv; char argv_r_[PADR_(uint32_t *)];
	char envv_l_[PADL_(uint32_t *)]; uint32_t * envv; char envv_r_[PADR_(uint32_t *)];
};
struct freebsd32_gettimeofday_args {
	char tp_l_[PADL_(struct timeval32 *)]; struct timeval32 * tp; char tp_r_[PADR_(struct timeval32 *)];
	char tzp_l_[PADL_(struct timezone *)]; struct timezone * tzp; char tzp_r_[PADR_(struct timezone *)];
};
struct freebsd32_settimeofday_args {
	char tv_l_[PADL_(const struct timeval32 *)]; const struct timeval32 * tv; char tv_r_[PADR_(const struct timeval32 *)];
	char tzp_l_[PADL_(const struct timezone *)]; const struct timezone * tzp; char tzp_r_[PADR_(const struct timezone *)];
};
struct freebsd32_utimes_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char tptr_l_[PADL_(const struct timeval32 *)]; const struct timeval32 * tptr; char tptr_r_[PADR_(const struct timeval32 *)];
};
struct freebsd32_adjtime_args {
	char delta_l_[PADL_(const struct timeval32 *)]; const struct timeval32 * delta; char delta_r_[PADR_(const struct timeval32 *)];
	char olddelta_l_[PADL_(struct timeval32 *)]; struct timeval32 * olddelta; char olddelta_r_[PADR_(struct timeval32 *)];
};
struct freebsd32_ntp_adjtime_args {
	char tp_l_[PADL_(struct timex32 *)]; struct timex32 * tp; char tp_r_[PADR_(struct timex32 *)];
};
struct freebsd32_nanosleep_args {
	char rqtp_l_[PADL_(const struct timespec32 *)]; const struct timespec32 * rqtp; char rqtp_r_[PADR_(const struct timespec32 *)];
	char rmtp_l_[PADL_(struct timespec32 *)]; struct timespec32 * rmtp; char rmtp_r_[PADR_(struct timespec32 *)];
};
struct freebsd32_ffclock_setestimate_args {
	char cest_l_[PADL_(struct ffclock_estimate32 *)]; struct ffclock_estimate32 * cest; char cest_r_[PADR_(struct ffclock_estimate32 *)];
};
struct freebsd32_ffclock_getestimate_args {
	char cest_l_[PADL_(struct ffclock_estimate32 *)]; struct ffclock_estimate32 * cest; char cest_r_[PADR_(struct ffclock_estimate32 *)];
};
struct freebsd32_aio_read_args {
	char aiocbp_l_[PADL_(struct aiocb32 *)]; struct aiocb32 * aiocbp; char aiocbp_r_[PADR_(struct aiocb32 *)];
};
struct freebsd32_aio_write_args {
	char aiocbp_l_[PADL_(struct aiocb32 *)]; struct aiocb32 * aiocbp; char aiocbp_r_[PADR_(struct aiocb32 *)];
};
struct freebsd32_lutimes_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char tptr_l_[PADL_(const struct timeval32 *)]; const struct timeval32 * tptr; char tptr_r_[PADR_(const struct timeval32 *)];
};
struct freebsd32_aio_return_args {
	char aiocbp_l_[PADL_(struct aiocb32 *)]; struct aiocb32 * aiocbp; char aiocbp_r_[PADR_(struct aiocb32 *)];
};
struct freebsd32_aio_error_args {
	char aiocbp_l_[PADL_(struct aiocb32 *)]; struct aiocb32 * aiocbp; char aiocbp_r_[PADR_(struct aiocb32 *)];
};
struct freebsd32_jail_args {
	char jail_l_[PADL_(struct jail32 *)]; struct jail32 * jail; char jail_r_[PADR_(struct jail32 *)];
};
struct freebsd32_sigtimedwait_args {
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
	char info_l_[PADL_(struct siginfo32 *)]; struct siginfo32 * info; char info_r_[PADR_(struct siginfo32 *)];
	char timeout_l_[PADL_(const struct timespec32 *)]; const struct timespec32 * timeout; char timeout_r_[PADR_(const struct timespec32 *)];
};
struct freebsd32_sigwaitinfo_args {
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
	char info_l_[PADL_(struct siginfo32 *)]; struct siginfo32 * info; char info_r_[PADR_(struct siginfo32 *)];
};
struct freebsd32_aio_waitcomplete_args {
	char aiocbp_l_[PADL_(uint32_t *)]; uint32_t * aiocbp; char aiocbp_r_[PADR_(uint32_t *)];
	char timeout_l_[PADL_(struct timespec32 *)]; struct timespec32 * timeout; char timeout_r_[PADR_(struct timespec32 *)];
};
struct freebsd32_sigreturn_args {
	char sigcntxp_l_[PADL_(const struct __ucontext32 *)]; const struct __ucontext32 * sigcntxp; char sigcntxp_r_[PADR_(const struct __ucontext32 *)];
};
struct freebsd32_getcontext_args {
	char ucp_l_[PADL_(struct __ucontext32 *)]; struct __ucontext32 * ucp; char ucp_r_[PADR_(struct __ucontext32 *)];
};
struct freebsd32_setcontext_args {
	char ucp_l_[PADL_(const struct __ucontext32 *)]; const struct __ucontext32 * ucp; char ucp_r_[PADR_(const struct __ucontext32 *)];
};
struct freebsd32_swapcontext_args {
	char oucp_l_[PADL_(struct __ucontext32 *)]; struct __ucontext32 * oucp; char oucp_r_[PADR_(struct __ucontext32 *)];
	char ucp_l_[PADL_(const struct __ucontext32 *)]; const struct __ucontext32 * ucp; char ucp_r_[PADR_(const struct __ucontext32 *)];
};
struct freebsd32_thr_suspend_args {
	char timeout_l_[PADL_(const struct timespec32 *)]; const struct timespec32 * timeout; char timeout_r_[PADR_(const struct timespec32 *)];
};
struct freebsd32_aio_mlock_args {
	char aiocbp_l_[PADL_(struct aiocb32 *)]; struct aiocb32 * aiocbp; char aiocbp_r_[PADR_(struct aiocb32 *)];
};
struct freebsd32_fhstat_args {
	char u_fhp_l_[PADL_(const struct fhandle *)]; const struct fhandle * u_fhp; char u_fhp_r_[PADR_(const struct fhandle *)];
	char sb_l_[PADL_(struct stat32 *)]; struct stat32 * sb; char sb_r_[PADR_(struct stat32 *)];
};
struct freebsd32_aio_writev_args {
	char aiocbp_l_[PADL_(struct aiocb32 *)]; struct aiocb32 * aiocbp; char aiocbp_r_[PADR_(struct aiocb32 *)];
};
struct freebsd32_aio_readv_args {
	char aiocbp_l_[PADL_(struct aiocb32 *)]; struct aiocb32 * aiocbp; char aiocbp_r_[PADR_(struct aiocb32 *)];
};
int	freebsd32_sigaltstack(struct thread *, struct freebsd32_sigaltstack_args *);
int	freebsd32_execve(struct thread *, struct freebsd32_execve_args *);
int	freebsd32_gettimeofday(struct thread *, struct freebsd32_gettimeofday_args *);
int	freebsd32_settimeofday(struct thread *, struct freebsd32_settimeofday_args *);
int	freebsd32_utimes(struct thread *, struct freebsd32_utimes_args *);
int	freebsd32_adjtime(struct thread *, struct freebsd32_adjtime_args *);
int	freebsd32_ntp_adjtime(struct thread *, struct freebsd32_ntp_adjtime_args *);
int	freebsd32_nanosleep(struct thread *, struct freebsd32_nanosleep_args *);
int	freebsd32_ffclock_setestimate(struct thread *, struct freebsd32_ffclock_setestimate_args *);
int	freebsd32_ffclock_getestimate(struct thread *, struct freebsd32_ffclock_getestimate_args *);
int	freebsd32_aio_read(struct thread *, struct freebsd32_aio_read_args *);
int	freebsd32_aio_write(struct thread *, struct freebsd32_aio_write_args *);
int	freebsd32_lutimes(struct thread *, struct freebsd32_lutimes_args *);
int	freebsd32_aio_return(struct thread *, struct freebsd32_aio_return_args *);
int	freebsd32_aio_error(struct thread *, struct freebsd32_aio_error_args *);
int	freebsd32_jail(struct thread *, struct freebsd32_jail_args *);
int	freebsd32_sigtimedwait(struct thread *, struct freebsd32_sigtimedwait_args *);
int	freebsd32_sigwaitinfo(struct thread *, struct freebsd32_sigwaitinfo_args *);
int	freebsd32_aio_waitcomplete(struct thread *, struct freebsd32_aio_waitcomplete_args *);
int	freebsd32_sigreturn(struct thread *, struct freebsd32_sigreturn_args *);
int	freebsd32_getcontext(struct thread *, struct freebsd32_getcontext_args *);
int	freebsd32_setcontext(struct thread *, struct freebsd32_setcontext_args *);
int	freebsd32_swapcontext(struct thread *, struct freebsd32_swapcontext_args *);
int	freebsd32_thr_suspend(struct thread *, struct freebsd32_thr_suspend_args *);
int	freebsd32_aio_mlock(struct thread *, struct freebsd32_aio_mlock_args *);
int	freebsd32_fhstat(struct thread *, struct freebsd32_fhstat_args *);
int	freebsd32_aio_writev(struct thread *, struct freebsd32_aio_writev_args *);
int	freebsd32_aio_readv(struct thread *, struct freebsd32_aio_readv_args *);

#ifdef COMPAT_43

struct ofreebsd32_stat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct ostat32 *)]; struct ostat32 * ub; char ub_r_[PADR_(struct ostat32 *)];
};
struct ofreebsd32_lstat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct ostat32 *)]; struct ostat32 * ub; char ub_r_[PADR_(struct ostat32 *)];
};
struct ofreebsd32_sigreturn_args {
	char sigcntxp_l_[PADL_(struct ia32_sigcontext3 *)]; struct ia32_sigcontext3 * sigcntxp; char sigcntxp_r_[PADR_(struct ia32_sigcontext3 *)];
};
struct ofreebsd32_sigstack_args {
	char nss_l_[PADL_(struct sigstack32 *)]; struct sigstack32 * nss; char nss_r_[PADR_(struct sigstack32 *)];
	char oss_l_[PADL_(struct sigstack32 *)]; struct sigstack32 * oss; char oss_r_[PADR_(struct sigstack32 *)];
};
int	ofreebsd32_stat(struct thread *, struct ofreebsd32_stat_args *);
int	ofreebsd32_lstat(struct thread *, struct ofreebsd32_lstat_args *);
int	ofreebsd32_sigreturn(struct thread *, struct ofreebsd32_sigreturn_args *);
int	ofreebsd32_sigstack(struct thread *, struct ofreebsd32_sigstack_args *);

#endif /* COMPAT_43 */


#ifdef COMPAT_FREEBSD4

struct freebsd4_freebsd32_statfs_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char buf_l_[PADL_(struct ostatfs32 *)]; struct ostatfs32 * buf; char buf_r_[PADR_(struct ostatfs32 *)];
};
struct freebsd4_freebsd32_fhstatfs_args {
	char u_fhp_l_[PADL_(const struct fhandle *)]; const struct fhandle * u_fhp; char u_fhp_r_[PADR_(const struct fhandle *)];
	char buf_l_[PADL_(struct ostatfs32 *)]; struct ostatfs32 * buf; char buf_r_[PADR_(struct ostatfs32 *)];
};
struct freebsd4_freebsd32_sigreturn_args {
	char sigcntxp_l_[PADL_(const struct freebsd4_ucontext32 *)]; const struct freebsd4_ucontext32 * sigcntxp; char sigcntxp_r_[PADR_(const struct freebsd4_ucontext32 *)];
};
int	freebsd4_freebsd32_statfs(struct thread *, struct freebsd4_freebsd32_statfs_args *);
int	freebsd4_freebsd32_fhstatfs(struct thread *, struct freebsd4_freebsd32_fhstatfs_args *);
int	freebsd4_freebsd32_sigreturn(struct thread *, struct freebsd4_freebsd32_sigreturn_args *);

#endif /* COMPAT_FREEBSD4 */


#ifdef COMPAT_FREEBSD6

struct freebsd6_freebsd32_aio_read_args {
	char aiocbp_l_[PADL_(struct oaiocb32 *)]; struct oaiocb32 * aiocbp; char aiocbp_r_[PADR_(struct oaiocb32 *)];
};
struct freebsd6_freebsd32_aio_write_args {
	char aiocbp_l_[PADL_(struct oaiocb32 *)]; struct oaiocb32 * aiocbp; char aiocbp_r_[PADR_(struct oaiocb32 *)];
};
int	freebsd6_freebsd32_aio_read(struct thread *, struct freebsd6_freebsd32_aio_read_args *);
int	freebsd6_freebsd32_aio_write(struct thread *, struct freebsd6_freebsd32_aio_write_args *);

#endif /* COMPAT_FREEBSD6 */


#ifdef COMPAT_FREEBSD7


#endif /* COMPAT_FREEBSD7 */


#ifdef COMPAT_FREEBSD10

struct freebsd10_freebsd32__umtx_lock_args {
	char umtx_l_[PADL_(struct umtx *)]; struct umtx * umtx; char umtx_r_[PADR_(struct umtx *)];
};
struct freebsd10_freebsd32__umtx_unlock_args {
	char umtx_l_[PADL_(struct umtx *)]; struct umtx * umtx; char umtx_r_[PADR_(struct umtx *)];
};
int	freebsd10_freebsd32__umtx_lock(struct thread *, struct freebsd10_freebsd32__umtx_lock_args *);
int	freebsd10_freebsd32__umtx_unlock(struct thread *, struct freebsd10_freebsd32__umtx_unlock_args *);

#endif /* COMPAT_FREEBSD10 */


#ifdef COMPAT_FREEBSD11

struct freebsd11_freebsd32_stat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct freebsd11_stat32 *)]; struct freebsd11_stat32 * ub; char ub_r_[PADR_(struct freebsd11_stat32 *)];
};
struct freebsd11_freebsd32_lstat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct freebsd11_stat32 *)]; struct freebsd11_stat32 * ub; char ub_r_[PADR_(struct freebsd11_stat32 *)];
};
struct freebsd11_freebsd32_nstat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct nstat32 *)]; struct nstat32 * ub; char ub_r_[PADR_(struct nstat32 *)];
};
struct freebsd11_freebsd32_nlstat_args {
	char path_l_[PADL_(const char *)]; const char * path; char path_r_[PADR_(const char *)];
	char ub_l_[PADL_(struct nstat32 *)]; struct nstat32 * ub; char ub_r_[PADR_(struct nstat32 *)];
};
struct freebsd11_freebsd32_fhstat_args {
	char u_fhp_l_[PADL_(const struct fhandle *)]; const struct fhandle * u_fhp; char u_fhp_r_[PADR_(const struct fhandle *)];
	char sb_l_[PADL_(struct freebsd11_stat32 *)]; struct freebsd11_stat32 * sb; char sb_r_[PADR_(struct freebsd11_stat32 *)];
};
int	freebsd11_freebsd32_stat(struct thread *, struct freebsd11_freebsd32_stat_args *);
int	freebsd11_freebsd32_lstat(struct thread *, struct freebsd11_freebsd32_lstat_args *);
int	freebsd11_freebsd32_nstat(struct thread *, struct freebsd11_freebsd32_nstat_args *);
int	freebsd11_freebsd32_nlstat(struct thread *, struct freebsd11_freebsd32_nlstat_args *);
int	freebsd11_freebsd32_fhstat(struct thread *, struct freebsd11_freebsd32_fhstat_args *);

#endif /* COMPAT_FREEBSD11 */


#ifdef COMPAT_FREEBSD12


#endif /* COMPAT_FREEBSD12 */

#define	FREEBSD32_SYS_AUE_ofreebsd32_stat	AUE_STAT
#define	FREEBSD32_SYS_AUE_ofreebsd32_lstat	AUE_LSTAT
#define	FREEBSD32_SYS_AUE_freebsd32_sigaltstack	AUE_SIGALTSTACK
#define	FREEBSD32_SYS_AUE_freebsd32_execve	AUE_EXECVE
#define	FREEBSD32_SYS_AUE_ofreebsd32_sigreturn	AUE_SIGRETURN
#define	FREEBSD32_SYS_AUE_ofreebsd32_sigstack	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_gettimeofday	AUE_GETTIMEOFDAY
#define	FREEBSD32_SYS_AUE_freebsd32_settimeofday	AUE_SETTIMEOFDAY
#define	FREEBSD32_SYS_AUE_freebsd32_utimes	AUE_UTIMES
#define	FREEBSD32_SYS_AUE_freebsd32_adjtime	AUE_ADJTIME
#define	FREEBSD32_SYS_AUE_freebsd4_freebsd32_statfs	AUE_STATFS
#define	FREEBSD32_SYS_AUE_freebsd32_ntp_adjtime	AUE_NTP_ADJTIME
#define	FREEBSD32_SYS_AUE_freebsd11_freebsd32_stat	AUE_STAT
#define	FREEBSD32_SYS_AUE_freebsd11_freebsd32_lstat	AUE_LSTAT
#define	FREEBSD32_SYS_AUE_freebsd32_nanosleep	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_ffclock_setestimate	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_ffclock_getestimate	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_aio_read	AUE_AIO_READ
#define	FREEBSD32_SYS_AUE_freebsd32_aio_write	AUE_AIO_WRITE
#define	FREEBSD32_SYS_AUE_freebsd32_lutimes	AUE_LUTIMES
#define	FREEBSD32_SYS_AUE_freebsd11_freebsd32_nstat	AUE_STAT
#define	FREEBSD32_SYS_AUE_freebsd11_freebsd32_nlstat	AUE_LSTAT
#define	FREEBSD32_SYS_AUE_freebsd4_freebsd32_fhstatfs	AUE_FHSTATFS
#define	FREEBSD32_SYS_AUE_freebsd11_freebsd32_fhstat	AUE_FHSTAT
#define	FREEBSD32_SYS_AUE_freebsd32_aio_return	AUE_AIO_RETURN
#define	FREEBSD32_SYS_AUE_freebsd32_aio_error	AUE_AIO_ERROR
#define	FREEBSD32_SYS_AUE_freebsd6_freebsd32_aio_read	AUE_AIO_READ
#define	FREEBSD32_SYS_AUE_freebsd6_freebsd32_aio_write	AUE_AIO_WRITE
#define	FREEBSD32_SYS_AUE_freebsd32_jail	AUE_JAIL
#define	FREEBSD32_SYS_AUE_freebsd4_freebsd32_sigreturn	AUE_SIGRETURN
#define	FREEBSD32_SYS_AUE_freebsd32_sigtimedwait	AUE_SIGWAIT
#define	FREEBSD32_SYS_AUE_freebsd32_sigwaitinfo	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_aio_waitcomplete	AUE_AIO_WAITCOMPLETE
#define	FREEBSD32_SYS_AUE_freebsd32_sigreturn	AUE_SIGRETURN
#define	FREEBSD32_SYS_AUE_freebsd32_getcontext	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_setcontext	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_swapcontext	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd10_freebsd32__umtx_lock	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd10_freebsd32__umtx_unlock	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_thr_suspend	AUE_NULL
#define	FREEBSD32_SYS_AUE_freebsd32_aio_mlock	AUE_AIO_MLOCK
#define	FREEBSD32_SYS_AUE_freebsd32_fhstat	AUE_FHSTAT
#define	FREEBSD32_SYS_AUE_freebsd32_aio_writev	AUE_AIO_WRITEV
#define	FREEBSD32_SYS_AUE_freebsd32_aio_readv	AUE_AIO_READV

#undef PAD_
#undef PADL_
#undef PADR_

#endif /* !_FREEBSD32_SYSPROTO_H_ */
