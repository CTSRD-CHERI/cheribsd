/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2002 Ian Dowse.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _SYS_SYSCALLSUBR_H_
#define _SYS_SYSCALLSUBR_H_

#include <sys/acl.h>
#include <sys/signal.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/mac.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/_cpuset.h>
#include <sys/_domainset.h>
#include <sys/_uio.h>

struct __wrusage;
struct cpuset_copy_cb;
struct ffclock_estimate;
struct file;
struct filecaps;
struct g_kevent_args;
enum idtype;
struct itimerval;
struct image_args;
struct in_addr;
struct in6_addr;
struct jail;
struct kevent_copyops;
struct kld_file_stat;
struct ksiginfo;
struct mbuf;
struct mmap_req;
struct msqid_ds;
struct ntptimeval;
struct pollfd;
struct ogetdirentries_args;
struct rlimit;
struct rusage;
struct rtprio;
struct sched_param;
struct sembuf;
union semun;
struct sockaddr;
struct spacectl_range;
struct stat;
struct thr_param;
struct timex;
struct uio;
struct uuid;
struct vm_map;
struct vmspace;

typedef int (*mmap_check_fp_fn)(struct file *, int, int, int);

struct mmap_req {
	vm_offset_t		mr_hint;
	vm_offset_t		mr_max_addr;
	vm_size_t		mr_len;
	int			mr_prot;
	int			mr_flags;
	int			mr_fd;
	int			mr_kern_flags;
	off_t			mr_pos;
	mmap_check_fp_fn	mr_check_fp_fn;
#if __has_feature(capabilities)
	void * __capability mr_source_cap;
#endif
};

int	kern___acl_aclcheck_fd(struct thread *td, int filedes, acl_type_t type,
	    const struct acl * __capability aclp);
int	kern___acl_aclcheck_path(struct thread *td,
	    const char * __capability path, acl_type_t type,
	    struct acl * __capability aclp, int follow);
int	kern___acl_delete_path(struct thread *td,
	    const char * __capability path, acl_type_t type, int follow);
int	kern___acl_get_fd(struct thread *td, int filedes, acl_type_t type,
	    struct acl * __capability aclp);
int	kern___acl_get_path(struct thread *td, const char * __capability path,
	    acl_type_t type, struct acl * __capability aclp, int follow);
int	kern___acl_set_fd(struct thread *td, int filedes, acl_type_t type,
	    const struct acl * __capability aclp);
int	kern___acl_set_path(struct thread *td, const char *__capability path,
	    acl_type_t type, const struct acl * __capability aclp, int follow);
int	kern___getcwd(struct thread *td, char * __capability buf,
	    size_t buflen);
int	kern___realpathat(struct thread *td, int fd,
	    const char * __capability path, char * __capability buf,
	    size_t size, int flags, enum uio_seg pathseg);
int	kern_abort2(struct thread *td, const char * __capability why,
            int nargs, void * __capability *uargs);
int	kern_accept(struct thread *td, int s, struct sockaddr **name,
	    socklen_t *namelen, struct file **fp);
int	kern_accept4(struct thread *td, int s, struct sockaddr **name,
	    socklen_t *namelen, int flags, struct file **fp);
int	kern_accessat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, int flags, int mode);
int	kern_acct(struct thread *td, const char * __capability path);
int	kern_adjtime(struct thread *td, struct timeval *delta,
	    struct timeval *olddelta);
int	kern_alternate_path(const char *prefix, const char * __capability path,
	    enum uio_seg pathseg, char **pathbuf, int create, int dirfd);
int	kern_audit(struct thread *td, const void * __capability record,
	    u_int length);
int	kern_auditctl(struct thread *td, const char * __capability path);
int	kern_auditon(struct thread *td, int cmd, void * __capability data,
	    u_int length);
int	kern_bindat(struct thread *td, int dirfd, int fd, struct sockaddr *sa);
int	kern_break(struct thread *td, uintptr_t *addr);
int	kern_cap_getmode(struct thread *td, u_int * __capability modep);
int	kern_cap_fcntls_get(struct thread *td, int fd,
	    uint32_t * __capability fcntlrightsp);
int	kern_cap_ioctls_get(struct thread *td, int fd,
	    u_long * __capability dstcmds, size_t maxcmds);
int	kern_cap_ioctls_limit(struct thread *td, int fd, u_long *cmds,
	    size_t ncmds);
int	kern_cap_rights_get(struct thread *td, int version, int fd,
	    cap_rights_t * __capability rightsp);
int	kern_cap_rights_limit(struct thread *td, int fd, cap_rights_t *rights);
int	kern_chdir(struct thread *td, const char * __capability path,
	    enum uio_seg pathseg);
int	kern_chflagsat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, u_long flags, int atflag);
int	kern_chroot(struct thread *td, const char * __capability path);
int	kern_clock_getcpuclockid2(struct thread *td, id_t id, int which,
	    clockid_t *clk_id);
int	kern_clock_getres(struct thread *td, clockid_t clock_id,
	    struct timespec *ts);
int	kern_clock_gettime(struct thread *td, clockid_t clock_id,
	    struct timespec *ats);
int	kern_clock_nanosleep(struct thread *td, clockid_t clock_id, int flags,
	    const struct timespec *rqtp, struct timespec *rmtp);
int	kern_clock_settime(struct thread *td, clockid_t clock_id,
	    struct timespec *ats);
void	kern_thread_cputime(struct thread *targettd, struct timespec *ats);
void	kern_process_cputime(struct proc *targetp, struct timespec *ats);
int	kern_close_range(struct thread *td, int flags, u_int lowfd, u_int highfd);
int	kern_close(struct thread *td, int fd);
int	kern_connectat(struct thread *td, int dirfd, int fd,
	    struct sockaddr *sa);
int	kern_copy_file_range(struct thread *td, int infd, off_t *inoffp,
	    int outfd, off_t *outoffp, size_t len, unsigned int flags);
int	kern_cpuset(struct thread *td, cpusetid_t * __capability setid);
int	kern_cpuset_getaffinity(struct thread *td, cpulevel_t level,
	    cpuwhich_t which, id_t id, size_t cpusetsize, cpuset_t *mask);
int	kern_cpuset_setaffinity(struct thread *td, cpulevel_t level,
	    cpuwhich_t which, id_t id, cpuset_t *maskp);
int	kern_cpuset_getdomain(struct thread *td, cpulevel_t level,
	    cpuwhich_t which, id_t id, size_t domainsetsize,
	    domainset_t * __capability maskp, int * __capability policyp,
	    const struct cpuset_copy_cb *cb);
int	kern_cpuset_setdomain(struct thread *td, cpulevel_t level,
	    cpuwhich_t which, id_t id, size_t domainsetsize,
	    const domainset_t * __capability maskp, int policy,
	    const struct cpuset_copy_cb *cb);
int	kern_cpuset_getid(struct thread *td, cpulevel_t level,
	    cpuwhich_t which, id_t id, cpusetid_t * __capability setid);
int	kern_cpuset_setid(struct thread *td, cpuwhich_t which,
	    id_t id, cpusetid_t setid);
int	kern_dup(struct thread *td, u_int mode, int flags, int old, int new);
int	kern_coexecve(struct thread *td, struct image_args *args,
	    void * __capability mac_p, struct vmspace *oldvmspace,
	    struct proc *cop, bool opportunistic);
int	kern_execve(struct thread *td, struct image_args *args,
	    void * __capability mac_p, struct vmspace *oldvmspace);
int	kern_extattrctl(struct thread *td, const char * __capability path,
	    int cmd, const char * __capability filename, int attrnamespace,
	    const char * __capability uattrname);
int	kern_extattr_delete_fd(struct thread *td, int fd, int attrnamespace,
	    const char * __capability uattrname);
int	kern_extattr_delete_path(struct thread *td,
	     const char * __capability path, int attrnamespace,
	     const char * __capability attrname, int follow);
int	kern_extattr_get_fd(struct thread *td, int fd, int attrnamespace,
	    const char * __capability attrname, void * __capability data,
	    size_t nbytes);
int	kern_extattr_get_path(struct thread *td, const char * __capability path,
	     int attrnamespace, const char * __capability attrname,
	     void * __capability data, size_t nbytes, int follow);
int	kern_extattr_list_fd(struct thread *td, int fd, int attrnamespace,
	    void * __capability data, size_t nbytes);
int	kern_extattr_list_path(struct thread *td,
	    const char * __capability path, int attrnamespace,
	    void * __capability data, size_t nbytes, int follow);
int	kern_extattr_set_fd(struct thread *td, int fd, int attrnamespace,
	    const char * __capability uattrname, void * __capability data,
	    size_t nbytes);
int	kern_extattr_set_path(struct thread *td, const char * __capability path,
	    int attrnamespace, const char * __capability attrname,
	    void * __capability data, size_t nbytes, int follow);
int	kern_fchmodat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, mode_t mode, int flag);
int	kern_fchownat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, int uid, int gid, int flag);
int	kern_fcntl(struct thread *td, int fd, int cmd, intptr_t arg);
int	kern_fcntl_freebsd(struct thread *td, int fd, int cmd, intcap_t arg);
int	kern_ffclock_getestimate(struct thread *td,
	    struct ffclock_estimate * __capability cest);
int	kern_ffclock_setestimate(struct thread *td,
	    const struct ffclock_estimate * __capability ucest);
int	kern_fhlinkat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, fhandle_t * __capability fhp);
int	kern_fhopen(struct thread *td,
	    const struct fhandle * __capability u_fhp, int flags);
int	kern_fhreadlink(struct thread *td, fhandle_t * __capability fhp,
	    char * __capability buf, size_t bufsize);
int	kern_fhstat(struct thread *td, fhandle_t fh, struct stat *buf);
int	kern_fhstatfs(struct thread *td, fhandle_t fh, struct statfs *buf);
int	kern_flag_captured(struct thread *td, const char * __capability message,
	    uint32_t key, const char *source);
int	kern_fpathconf(struct thread *td, int fd, int name, long *valuep);
int	kern_freebsd11_getfsstat(struct thread *td,
	    struct freebsd11_statfs * __capability ubuf, long bufsize,
	    int mode);
int	kern_fstat(struct thread *td, int fd, struct stat *sbp);
int	kern_fstatfs(struct thread *td, int fd, struct statfs *buf);
int	kern_fsync(struct thread *td, int fd, bool fullsync);
int	kern_ftruncate(struct thread *td, int fd, off_t length);
int	kern_futimes(struct thread *td, int fd,
	    const struct timeval * __capability tptr,
	    enum uio_seg tptrseg);
int	kern_futimens(struct thread *td, int fd,
	    const struct timespec * __capability tptr, enum uio_seg tptrseg);
int	kern_getaudit(struct thread *td,
	    struct auditinfo * __capability auditinfo);
int	kern_getaudit_addr(struct thread *td,
	    struct auditinfo_addr * __capability auditinfo_addr, u_int length);
int	kern_getauid(struct thread *td, uid_t * __capability auid);
int	kern_getdirentries(struct thread *td, int fd, char * __capability buf,
	    size_t count, off_t *basep, ssize_t *residp, enum uio_seg bufseg);
int	kern_getfhat(struct thread *td, int flags, int fd,
	    const char * __capability path, enum uio_seg pathseg,
	    fhandle_t * __capability fhp, enum uio_seg fhseg);
int	kern_getfsstat(struct thread *td, struct statfs * __capability *buf,
	    size_t bufsize, size_t *countp, enum uio_seg bufseg, int mode);
int	kern_getgroups(struct thread *td, int gidsetsize,
	    gid_t * __capability gidset);
int	kern_getitimer(struct thread *, u_int, struct itimerval *);
int	kern_getlogin(struct thread *td, char * __capability namebuf,
	    u_int namelen);
int	kern_getloginclass(struct thread *td, char * __capability namebuf,
	    size_t namelen);
int	kern_getppid(struct thread *);
int	kern_getpeername(struct thread *td, int fd, struct sockaddr **sa,
	    socklen_t *alen);
int	kern_getpriority(struct thread *td, int which, int who);
int	kern_getrandom(struct thread *td, void * __capability user_buf,
	    size_t buflen, unsigned int flags);
int	kern_getresgid(struct thread *td, gid_t * __capability rgid,
	    gid_t * __capability egid, gid_t * __capability sgid);
int	kern_getresuid(struct thread *td, uid_t * __capability ruid,
	    uid_t * __capability euid, uid_t * __capability suid);
int	kern_getrusage(struct thread *td, int who, struct rusage *rup);
int	kern_getsid(struct thread *td, pid_t pid);
int	kern_getsockname(struct thread *td, int fd, struct sockaddr **sa,
	    socklen_t *alen);
int	kern_getsockopt(struct thread *td, int s, int level, int name,
	    void * __capability val, enum uio_seg valseg, socklen_t *valsize);
int	kern_gettimeofday(struct thread *td,
	    struct timeval * __capability tp,
	    struct timezone * __capability tzp);
int	kern_ioctl(struct thread *td, int fd, u_long com, caddr_t data);
int	kern_jail(struct thread *td, const char * __capability path,
	    const char * __capability hostname,
	    const char * __capability jailname,
	    struct in_addr * __capability ip4, size_t ip4s,
	    struct in6_addr * __capability ip6, size_t ip6s,
	    enum uio_seg ipseg);
int	kern_jail_get(struct thread *td, struct uio *options, int flags);
int	kern_jail_set(struct thread *td, struct uio *options, int flags);
int	kern_kenv(struct thread *td, int what, const char * __capability namep,
	    char * __capability val, int vallen);
int	kern_kevent(struct thread *td, int fd, int nchanges, int nevents,
	    struct kevent_copyops *k_ops, const struct timespec *timeout);
int	kern_kevent_generic(struct thread *td, struct g_kevent_args *uap,
	    struct kevent_copyops *k_ops, const char *struct_name);
int	kern_kevent_anonymous(struct thread *td, int nevents,
	    struct kevent_copyops *k_ops);
int	kern_kevent_fp(struct thread *td, struct file *fp, int nchanges,
	    int nevents, struct kevent_copyops *k_ops,
	    const struct timespec *timeout);
int	kern_kill(struct thread *td, pid_t pid, int signum);
int	kern_kqueue(struct thread *td, int flags, struct filecaps *fcaps);
int	kern_kldfind(struct thread *td, const char * __capability file);
int	kern_kldload(struct thread *td, const char *file, int *fileid);
int	kern_kldstat(struct thread *td, int fileid, struct kld_file_stat *stat);
int	kern_kldsym(struct thread *td, int fileid, int cmd,
	    const char * __capability symstr, u_long *symvalue,
	    size_t *symsize);
int	kern_kldunload(struct thread *td, int fileid, int flags);
int	kern_ktrace(struct thread *td, const char * __capability fname,
	    int uops, int ufacs, int pid);
int	kern_linkat(struct thread *td, int fd1, int fd2,
	    const char * __capability path1, const char * __capability path2,
	    enum uio_seg segflg, int flag);
int	kern_listen(struct thread *td, int s, int backlog);
int	kern_lseek(struct thread *td, int fd, off_t offset, int whence);
int	kern_lutimes(struct thread *td,
	    const char * __capability path, enum uio_seg pathseg,
	    const struct timeval * __capability tptr, enum uio_seg tptrseg);
int	kern_mac_get_fd(struct thread *td, int fd, void * __capability mac_p);
int	kern_mac_get_pid(struct thread *td, pid_t pid,
	    void * __capability mac_p);
int	kern_mac_get_path(struct thread *td, const char * __capability path_p,
	    void * __capability mac_p, int follow);
int	kern_mac_get_proc(struct thread *td, void * __capability mac_p);
int	kern_mac_set_fd(struct thread *td, int fd, void * __capability mac_p);
int	kern_mac_set_path(struct thread *td, const char * __capability path_p,
	    void * __capability mac_p, int follow);
int	kern_mac_set_proc(struct thread *td, void * __capability mac_p);
int	kern_mac_syscall(struct thread *td, const char * __capability policy,
	    int call, void * __capability arg);
int	kern_madvise(struct thread *td, uintptr_t addr, size_t len, int behav);
int	kern_mincore(struct thread *td, uintptr_t addr, size_t len,
	    char * __capability vec);
int	kern_minherit(struct thread *td, uintptr_t addr, size_t len,
	    int inherit);
int	kern_mkdirat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg segflg, int mode);
int	kern_mkfifoat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, int mode);
int	kern_mknodat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, int mode, dev_t dev);
int	kern_mlock(struct proc *proc, struct ucred *cred, uintptr_t addr,
	    size_t len);
int	kern_mmap(struct thread *td, const struct mmap_req *mrp);
int	kern_mmap_maxprot(struct proc *p, int prot);
int	kern_mmap_racct_check(struct thread *td, struct vm_map *map,
	    vm_size_t size);
int	kern_modfind(struct thread *td, const char * __capability uname);
int	kern_modstat(struct thread *td, int modid,
	    struct module_stat * __capability stat);
int	kern_mprotect(struct thread *td, uintptr_t addr, size_t size, int prot);
int	kern_msgctl(struct thread *, int, int, struct msqid_ds *);
int	kern_msgrcv(struct thread *, int, void * __capability, size_t, long,
	    int, long *);
int	kern_msgsnd(struct thread *, int, const void * __capability, size_t,
	    int, long);
int	kern_msync(struct thread *td, uintptr_t addr, size_t size, int flags);
int	kern_munlock(struct thread *td, uintptr_t addr, size_t size);
int	kern_munmap(struct thread *td, uintptr_t addr, size_t size);
int     kern_nanosleep(struct thread *td, struct timespec *rqt,
	    struct timespec *rmt);
int	kern_nmount(struct thread *td, struct iovec * __capability iovp,
	    u_int iovcnt, int flags32, copyinuio_t * copyinuio_f);
int	kern_ntp_adjtime(struct thread *td, struct timex *ntv, int *retvalp);
int	kern_ntp_gettime(struct thread *td,
	    struct ntptimeval * __capability ntvp);
int	kern_ogetdirentries(struct thread *td, struct ogetdirentries_args *uap,
	    long *ploff);
int	kern_ommap(struct thread *td, uintptr_t hint, int len, int oprot,
	    int oflags, int fd, long pos);
int	kern_openat(struct thread *td, int fd, char const * __capability path,
	    enum uio_seg pathseg, int flags, int mode);
int	kern_pathconf(struct thread *td, const char * __capability path,
	    enum uio_seg pathseg, int name, u_long flags, long *valuep);
int	kern_pdfork(struct thread *td, int * __capability fdp, int flags);
int	kern_pipe(struct thread *td, int fildes[2], int flags,
	    struct filecaps *fcaps1, struct filecaps *fcaps2);
int	kern_pipe2(struct thread *td, int * __capability ufildes, int flags);
int	kern_poll(struct thread *td, struct pollfd * __capability fds,
	    u_int nfds, struct timespec *tsp, sigset_t *uset);
int	kern_poll_kfds(struct thread *td, struct pollfd *fds, u_int nfds,
	    struct timespec *tsp, sigset_t *uset);
bool	kern_poll_maxfds(u_int nfds);
int	kern_posix_error(struct thread *td, int error);
int	kern_posix_fadvise(struct thread *td, int fd, off_t offset, off_t len,
	    int advice);
int	kern_posix_fallocate(struct thread *td, int fd, off_t offset,
	    off_t len);
int	kern_fspacectl(struct thread *td, int fd, int cmd,
	    const struct spacectl_range *, int flags, struct spacectl_range *);
int	kern_procctl(struct thread *td, enum idtype idtype, id_t id, int com,
	    void *data);
int	kern_profil(struct thread *td, char * __capability samples, size_t size,
	    size_t offset, u_int scale);
int	kern_pread(struct thread *td, int fd, void * __capability buf,
	    size_t nbyte, off_t offset);
int	kern_preadv(struct thread *td, int fd, struct uio *auio, off_t offset);
int	kern_pselect(struct thread *td, int nd, fd_set * __capability in,
	    fd_set * __capability ou, fd_set * __capability ex,
	    struct timeval *tvp, sigset_t *uset, int abi_nfdbits);
int	kern_ptrace(struct thread *td, int req, pid_t pid, void * __capability addr,
	    int data);
int	kern_pwrite(struct thread *td, int fd, const void * __capability buf,
	    size_t nbyte, off_t offset);
int	kern_pwritev(struct thread *td, int fd, struct uio *auio, off_t offset);
int	kern_quotactl(struct thread *td, const char * __capability path,
	    int cmd, int uid, void * __capability arg);
int	kern_rctl_get_racct(struct thread *td,
	    const void * __capability inbufp, size_t inbuflen,
	    void * __capability outbufp, size_t outbuflen);
int	kern_rctl_get_rules(struct thread *td,
	    const void * __capability inbufp, size_t inbuflen,
	    void * __capability outbufp, size_t outbuflen);
int	kern_rctl_get_limits(struct thread *td,
	    const void * __capability inbufp, size_t inbuflen,
	    void * __capability outbufp, size_t outbuflen);
int	kern_rctl_add_rule(struct thread *td,
	    const void * __capability inbufp, size_t inbuflen,
	    void * __capability outbufp, size_t outbuflen);
int	kern_rctl_remove_rule(struct thread *td,
	    const void * __capability inbufp, size_t inbuflen,
	    void * __capability outbufp, size_t outbuflen);
int	kern_readlinkat(struct thread *td, int fd,
	    const char * __capability path, enum uio_seg pathseg,
	    char * __capability buf, enum uio_seg bufseg, size_t count);
int	kern_readv(struct thread *td, int fd, struct uio *auio);
int	kern_recvfrom(struct thread *td, int s, void * __capability buf,
	    size_t len, int flags,
	    struct sockaddr * __capability __restrict from,
	    socklen_t * __capability __restrict fromlenaddr);
int	kern_recvit(struct thread *td, int s, struct msghdr *mp,
	    enum uio_seg fromseg, struct mbuf **controlp);
int	kern_renameat(struct thread *td, int oldfd,
	    const char * __capability old, int newfd,
	    const char * __capability new, enum uio_seg pathseg);
int	kern_revoke(struct thread *td, const char * __capability path,
	    enum uio_seg pathseg);
int	kern_frmdirat(struct thread *td, int dfd,
	    const char * __capability path, int fd, enum uio_seg pathseg,
	    int flag);
int	kern_rtprio(struct thread *td, int function, pid_t pid,
	    struct rtprio * __capability urtp);
int	kern_rtprio_thread(struct thread *td, int function, lwpid_t lwpid,
	    struct rtprio * __capability urtp);
int	kern_sched_getparam(struct thread *td, struct thread *targettd,
	    struct sched_param *param);
int	kern_sched_getscheduler(struct thread *td, struct thread *targettd,
	    int *policy);
int	kern_sched_setparam(struct thread *td, struct thread *targettd,
	    struct sched_param *param);
int	kern_sched_setscheduler(struct thread *td, struct thread *targettd,
	    int policy, struct sched_param *param);
int	kern_sched_rr_get_interval(struct thread *td, pid_t pid,
	    struct timespec *ts);
int	kern_sched_rr_get_interval_td(struct thread *td, struct thread *targettd,
	    struct timespec *ts);
int	kern_semctl(struct thread *td, int semid, int semnum, int cmd,
	    union semun *arg, register_t *rval);
int	kern_sendfile(struct thread *td, int fd, int s, off_t offset,
	    size_t nbytes, void * __capability uhdtr,
	    off_t * __capability usbytes, int flags, int compat,
	    copyin_hdtr_t *copyin_hdtr_f, copyinuio_t *copyinuio_f);
int	kern_setaudit(struct thread *td,
	    struct auditinfo * __capability auditinfo);
int	kern_setaudit_addr(struct thread *td,
	    struct auditinfo_addr * __capability auditinfo_addr, u_int length);
int	kern_setauid(struct thread *td, uid_t * __capability auid);
int	kern_setlogin(struct thread *td, const char * __capability namebuf);
int	kern_setloginclass(struct thread *td,
	    const char * __capability namebuf);
int	kern_select(struct thread *td, int nd, fd_set * __capability fd_in,
	    fd_set * __capability fd_ou, fd_set * __capability fd_ex,
	    struct timeval *tvp, int abi_nfdbits);
int	kern_sendit(struct thread *td, int s, struct msghdr *mp, int flags,
	    struct mbuf *control, enum uio_seg segflg);
int	kern_setgroups(struct thread *td, u_int ngrp, gid_t *groups);
int	kern_setitimer(struct thread *, u_int, struct itimerval *,
	    struct itimerval *);
int	kern_setpriority(struct thread *td, int which, int who, int prio);
int	kern_setrlimit(struct thread *, u_int, struct rlimit *);
int	kern_setsockopt(struct thread *td, int s, int level, int name,
	    const void * __capability val, enum uio_seg valseg,
	    socklen_t valsize);
int	kern_settimeofday(struct thread *td, struct timeval *tv,
	    struct timezone *tzp);
int	kern_shm_open(struct thread *td, const char * __capability userpath,
	    int flags, mode_t mode, struct filecaps *fcaps);
int	kern_shm_open2(struct thread *td, const char * __capability path,
	    int flags, mode_t mode, int shmflags, struct filecaps *fcaps,
	    const char * __capability name);
int	kern_shm_rename(struct thread *td,
	    const char * __capability path_from_p,
	    const char * __capability path_to_p, int flags);
int	kern_shm_unlink(struct thread *td, const char * __capability userpath);
int	kern_shmctl(struct thread *td, int shmid, int cmd, void *buf,
	    size_t *bufsz);
int	kern_shutdown(struct thread *td, int s, int how);
int	kern_sigaction(struct thread *td, int sig, const struct sigaction *act,
	    struct sigaction *oact, int flags);
int	kern_sigaltstack(struct thread *td, stack_t *ss, stack_t *oss);
int	kern_sigfastblock(struct thread *td, int cmd,
	    uint32_t * __capability ptr);
int	kern_sigpending(struct thread *td, sigset_t * __capability set);
int	kern_sigprocmask(struct thread *td, int how,
	    sigset_t *set, sigset_t *oset, int flags);
int	kern_sigsuspend(struct thread *td, sigset_t mask);
int	kern_sigtimedwait(struct thread *td, sigset_t waitset,
	    struct ksiginfo *ksi, struct timespec *timeout);
int	kern_sigqueue(struct thread *td, pid_t pid, int signum,
	    union sigval *value);
int	kern_socket(struct thread *td, int domain, int type, int protocol);
int	kern_statat(struct thread *td, int flag, int fd,
	    const char * __capability path,
	    enum uio_seg pathseg, struct stat *sbp,
	    void (*hook)(struct vnode *vp, struct stat *sbp));
int	kern_specialfd(struct thread *td, int type, void * __capability arg);
int	kern_statfs(struct thread *td, const char * __capability path,
	    enum uio_seg pathseg, struct statfs *buf);
int	kern_swapoff(struct thread *td, const char * __capability name,
	    enum uio_seg name_seg, u_int flags);
int	kern_swapon(struct thread *td, const char * __capability name);
int	kern_symlinkat(struct thread *td, const char *__capability path1,
	    int fd, const char * __capability path2, enum uio_seg segflg);
int	kern_sync(struct thread *td);
int	kern_sysctl(struct thread *td, int * __capability uname,
	    u_int namelen,
	    void * __capability old, size_t * __capability oldlenp,
	    const void * __capability new, size_t newlen, int flags);
int	kern_ktimer_create(struct thread *td, clockid_t clock_id,
	    struct sigevent *evp, int *timerid, int preset_id);
int	kern_ktimer_delete(struct thread *, int);
int	kern_ktimer_settime(struct thread *td, int timer_id, int flags,
	    struct itimerspec *val, struct itimerspec *oval);
int	kern_ktimer_gettime(struct thread *td, int timer_id,
	    struct itimerspec *val);
int	kern_ktimer_getoverrun(struct thread *td, int timer_id);
int	kern_semop(struct thread *td, int usemid,
	    struct sembuf * __capability usops, size_t nsops,
	    struct timespec *timeout);
int	kern_thr_alloc(struct proc *, int pages, struct thread **);
int	kern_thr_exit(struct thread *td);
int	kern_thr_new(struct thread *td, struct thr_param *param);
int	kern_thr_set_name(struct thread *td, lwpid_t id,
	    const char * __capability uname);
int	kern_thr_suspend(struct thread *td, struct timespec *tsp);
int	kern_truncate(struct thread *td, const char * __capability path,
	    enum uio_seg pathseg, off_t length);
int	kern_undelete(struct thread *td, const char * __capability path,
	    enum uio_seg pathseg);
int	kern_funlinkat(struct thread *td, int dfd,
	    const char * __capability path, int fd, enum uio_seg pathseg,
	    int flag, ino_t oldinum);
int	kern_funlinkat_ex(struct thread *td, int dfd,
	    const char * __capability path, int fd, int flag,
	    enum uio_seg pathseg, ino_t oldinum);
int	kern_unlinkat(struct thread *td, int fd,
	    const char * __capability path, enum uio_seg pathseg,
	    int flag, ino_t oldinum);
int	kern_utimesat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, const struct timeval * __capability tptr,
	    enum uio_seg tptrseg);
int	kern_utimensat(struct thread *td, int fd, const char * __capability path,
	    enum uio_seg pathseg, const struct timespec * __capability tptr,
	    enum uio_seg tptrseg, int flag);
int	kern_utrace(struct thread *td, const void * __capability addr,
	    size_t len);
int	kern_wait(struct thread *td, pid_t pid, int *status, int options,
	    struct rusage *rup);
int	kern_wait4(struct thread *td, int pid, int * __capability status,
	    int options, struct rusage * __capability rusage);
int	kern_wait6(struct thread *td, enum idtype idtype, id_t id, int *status,
	    int options, struct __wrusage *wrup, siginfo_t *sip);
int	kern_write(struct thread *td, int fd, const void * __capability buf,
	    size_t nbyte);
int	kern_writev(struct thread *td, int fd, struct uio *auio);
int	kern_socketpair(struct thread *td, int domain, int type, int protocol,
	    int *rsv);
int	kern_unmount(struct thread *td, const char * __capability path,
	    int flags);

int	user_accept(struct thread *td, int s,
	    struct sockaddr * __capability uname,
	    socklen_t * __capability anamelen, int flags);
int	user_bind(struct thread *td, int s,
	    const struct sockaddr * __capability name, socklen_t namelen);
int	user_bindat(struct thread *td, int fd, int s,
	    const struct sockaddr * __capability name, socklen_t namelen);
int	user_cap_ioctls_limit(struct thread *td, int fd,
	    const u_long * __capability ucmds, size_t ncmds);
int	user_cap_rights_limit(struct thread *td, int fd,
	    cap_rights_t * __capability rightsp);
int	user_clock_nanosleep(struct thread *td, clockid_t clock_id,
	    int flags, const struct timespec * __capability ua_rqtp,
	    struct timespec * __capability ua_rmtp);
int	user_connectat(struct thread *td, int fd, int s,
		const struct sockaddr * __capability name, socklen_t namelen);
int	user_copy_file_range(struct thread *td,
	    int infd, off_t * __capability inoffp,
	    int outfd, off_t * __capability outoffp,
	    size_t len, unsigned int flags);
int	user_cpuset_getaffinity(struct thread *td, cpulevel_t level,
	    cpuwhich_t which, id_t id, size_t cpusetsize,
	    cpuset_t * __capability maskp,
	    const struct cpuset_copy_cb *cb);
int	user_cpuset_setaffinity(struct thread *td, cpulevel_t level,
	    cpuwhich_t which, id_t id, size_t cpusetsize,
	    const cpuset_t * __capability maskp,
	    const struct cpuset_copy_cb *cb);
int	user_fhstat(struct thread *td,
	    const struct fhandle * __capability u_fhp,
	    struct stat * __capability sb);
int	user_fhstatfs(struct thread *td,
	    const struct fhandle * __capability u_fhp,
	    struct statfs * __capability buf);
int	user_fspacectl(struct thread *td, int fd, int cmd,
	    const struct spacectl_range * __capability rqsrp, int flags,
	    struct spacectl_range * __capability rmsrp);
int	user_fstat(struct thread *td, int fd, struct stat * __capability sb);
int	user_fstatat(struct thread *td, int fd, const char * __capability path,
	    struct stat * __capability buf, int flag);
int	user_fstatfs(struct thread *td, int fd,
	    struct statfs * __capability buf);
int	user_getdirentries(struct thread *td, int fd, char * __capability buf,
	    size_t count, off_t * __capability basep);
int	user_getfsstat(struct thread *td, struct statfs * __capability buf,
	    long bufsize, int mode);
int	user_getpeername(struct thread *td, int fdes,
	    struct sockaddr * __restrict __capability asa,
	    socklen_t * __capability alen, bool compat);
int	user_getsockname(struct thread *td, int fdes,
	    struct sockaddr * __restrict __capability asa,
	    socklen_t * __capability alen, bool compat);
int	user_getsockopt(struct thread *td, int s, int level, int name,
	    void * __capability val, socklen_t * __capability avalsize);
int	user_ioctl(struct thread *td, int fd, u_long com,
	    void * __capability udata, void *datap, int copycaps);
int	user_jail_get(struct thread *td, struct iovec * __capability iovp,
	    unsigned int iovcnt, int flags, copyinuio_t *copyinuio_f,
	    updateiov_t *updateiov_f);
int	user_jail_set(struct thread *td, struct iovec * __capability iovp,
	    unsigned int iovcnt, int flags, copyinuio_t *copyinuio_f);
int	user_kldload(struct thread *td, const char * __capability file);
int	user_pdgetpid(struct thread *td, int fd, pid_t * __capability pidp);
int	user_poll(struct thread *td, struct pollfd * __capability fds,
	    u_int nfds, int timeout);
int	user_ppoll(struct thread *td, struct pollfd *__capability fds,
	    u_int nfds, const struct timespec * __capability uts,
	    const sigset_t * __capability uset);
int	user_preadv(struct thread *td, int fd, struct iovec * __capability iovp,
	    u_int iovcnt, off_t offset, copyinuio_t *copyinuio_f);
int	user_pselect(struct thread *td, int nd, fd_set * __capability in,
	    fd_set * __capability ou, fd_set * __capability ex,
	    const struct timespec * __capability uts,
	    const sigset_t * __capability sm);
int	user_pwritev(struct thread *td, int fd, struct iovec * __capability iovp,
	    u_int iovcnt, off_t offset, copyinuio_t *copyinuio_f);
int	user_read(struct thread *td, int fd, void * __capability buf,
	    size_t nbyte);
int	user_readv(struct thread *td, int fd, struct iovec * __capability iovp,
	    u_int iovcnt, copyinuio_t *copyinuio_f);
int	user_sched_getparam(struct thread *td, pid_t,
	    struct sched_param * __capability param);
int	user_sched_rr_get_interval(struct thread *td, pid_t pid,
	    struct timespec * __capability interval);
int	user_sched_setparam(struct thread *td, pid_t pid,
	    const struct sched_param * __capability param);
int	user_sched_setscheduler(struct thread *td, pid_t pid, int policy,
	    const struct sched_param * __capability param);
int	user_select(struct thread *td, int nd, fd_set * __capability in,
	    fd_set * __capability ou, fd_set * __capability ex,
	    struct timeval * __capability utv);
int	user_sendit(struct thread *td, int s, struct msghdr *mp, int flags);
int	user_sendto(struct thread *td, int s, const char * __capability buf,
	    size_t len, int flags, const struct sockaddr * __capability to,
	    socklen_t tolen);
int	user_setgroups(struct thread *td, int gidsetsize,
	    const gid_t * __capability gidset);
int	user_settimeofday(struct thread *td,
	    const struct timeval * __capability tp,
	    const struct timezone * __capability tz);
int	user_sigprocmask(struct thread *td, int how,
	    const sigset_t * __capability uset, sigset_t * __capability uoset);
int	user_sigsuspend(struct thread *td,
	    const sigset_t * __capability sigmask);
int	user_sigtimedwait(struct thread *td,
	    const sigset_t * __capability uset, void * __capability info,
	    const struct timespec * __capability utimeout,
	    copyout_siginfo_t *copyout_siginfop);
int	user_sigwait(struct thread *td, const sigset_t * __capability uset,
	    int * __capability usig);
int	user_sigwaitinfo(struct thread *td, const sigset_t * __capability uset,
	    void * __capability info, copyout_siginfo_t *copyout_siginfop);
int	user_socketpair(struct thread *td, int domain, int type, int protocol,
	    int * __capability rsv);
int	user_specialfd(struct thread *td, int type, const void * __capability req,
	    size_t len);
int	user_statfs(struct thread *td, const char * __capability path,
	    struct statfs * __capability buf);
int	user_uuidgen(struct thread *td, struct uuid * __capability storep,
	    int count);
int	user_wait6(struct thread *td, enum idtype idtype, id_t id,
	    int * __capability statusp, int options,
	    struct __wrusage * __capability wrusage, siginfo_t *sip);
int	user_writev(struct thread *td, int fd, struct iovec * __capability iovp,
	    u_int iovcnt, copyinuio_t *copyinuio_f);

/* flags for kern_sigaction */
#define	KSA_OSIGSET	0x0001	/* uses osigact_t */
#define	KSA_FREEBSD4	0x0002	/* uses ucontext4 */

struct freebsd11_dirent;

int	freebsd11_kern_getdirentries(struct thread *td, int fd,
	    char * __capability ubuf, u_int count, long *basep,
	    void (*func)(struct freebsd11_dirent *));

int	kern_cosetup(struct thread *td, int what,
	    void * __capability * __capability codep,
	    void * __capability * __capability datap);
int	kern_coregister(struct thread *td, const char * __capability namep,
	    void * __capability * __capability capp);
int	kern_colookup(struct thread *td, const char * __capability namep,
	    void * __capability * __capability capp);
int	kern_cogetpid(struct thread *td, pid_t * __capability pidp);
int	kern_copark(struct thread *td);
int	kern_cocall_slow(void * __capability target,
	    const void * __capability outbuf, size_t outlen,
	    void * __capability inbuf, size_t inlen);
int	kern_coaccept_slow(void * __capability * __capability cookiep,
	    const void * __capability outbuf, size_t outlen,
	    void * __capability inbuf, size_t inlen);

#endif /* !_SYS_SYSCALLSUBR_H_ */
// CHERI CHANGES START
// {
//   "updated": 20221205,
//   "target_type": "header",
//   "changes": [
//     "user_capabilities"
//   ]
// }
// CHERI CHANGES END
