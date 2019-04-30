/*-
 * Copyright (c) 2015-2019 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of
 * the DARPA SSITH research programme.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>

#include <compat/freebsd64/freebsd64_proto.h>

/*
 * vfs_acl.c
 */
int
freebsd64___acl_get_file(struct thread *td,
    struct freebsd64___acl_get_file_args *uap)
{

	return (kern___acl_get_path(td, __USER_CAP_STR(uap->path), uap->type,
	    __USER_CAP_OBJ(uap->aclp), FOLLOW));
}

int
freebsd64___acl_get_link(struct thread *td,
    struct freebsd64___acl_get_link_args *uap)
{

	return (kern___acl_get_path(td, __USER_CAP_STR(uap->path), uap->type,
	    __USER_CAP_OBJ(uap->aclp), NOFOLLOW));
}

int
freebsd64___acl_set_file(struct thread *td,
    struct freebsd64___acl_set_file_args *uap)
{

	return(kern___acl_set_path(td, __USER_CAP_STR(uap->path), uap->type,
	    __USER_CAP_OBJ(uap->aclp), FOLLOW));
}

int
freebsd64___acl_set_link(struct thread *td,
    struct freebsd64___acl_set_link_args *uap)
{

	return(kern___acl_set_path(td, __USER_CAP_STR(uap->path), uap->type,
	    __USER_CAP_OBJ(uap->aclp), NOFOLLOW));
}

int
freebsd64___acl_get_fd(struct thread *td,
    struct freebsd64___acl_get_fd_args *uap)
{

	return (kern___acl_get_fd(td, uap->filedes, uap->type,
	    __USER_CAP_OBJ(uap->aclp)));
}

int
freebsd64___acl_set_fd(struct thread *td,
    struct freebsd64___acl_set_fd_args *uap)
{

	return (kern___acl_set_fd(td, uap->filedes, uap->type,
	    __USER_CAP_OBJ(uap->aclp)));
}

int
freebsd64___acl_delete_file(struct thread *td,
    struct freebsd64___acl_delete_file_args *uap)
{

	return (kern___acl_delete_path(td, __USER_CAP_STR(uap->path),
	    uap->type, FOLLOW));
}

int
freebsd64___acl_delete_link(struct thread *td,
    struct freebsd64___acl_delete_link_args *uap)
{

	return (kern___acl_delete_path(td, __USER_CAP_STR(uap->path),
	    uap->type, NOFOLLOW));
}

int
freebsd64___acl_aclcheck_file(struct thread *td,
    struct freebsd64___acl_aclcheck_file_args *uap)
{

	return (kern___acl_aclcheck_path(td, __USER_CAP_STR(uap->path),
	    uap->type, __USER_CAP_OBJ(uap->aclp), FOLLOW));
}

int
freebsd64___acl_aclcheck_link(struct thread *td,
    struct freebsd64___acl_aclcheck_link_args *uap)
{

	return (kern___acl_aclcheck_path(td, __USER_CAP_STR(uap->path),
	    uap->type, __USER_CAP_OBJ(uap->aclp), NOFOLLOW));
}

int
freebsd64___acl_aclcheck_fd(struct thread *td,
    struct freebsd64___acl_aclcheck_fd_args *uap)
{

	return (kern___acl_aclcheck_fd(td, uap->filedes, uap->type,
	    __USER_CAP_OBJ(uap->aclp)));
}

/*
 * vfs_cache.c
 */
int
freebsd64___getcwd(struct thread *td, struct freebsd64___getcwd_args *uap)
{

	return (kern___getcwd(td, __USER_CAP(uap->buf, uap->buflen),
	    UIO_USERSPACE, uap->buflen, MAXPATHLEN));
}

/*
 * vfs_extattr.c
 */
int
freebsd64_extattrctl(struct thread *td, struct freebsd64_extattrctl_args *uap)
{

	return (kern_extattrctl(td, __USER_CAP_STR(uap->path), uap->cmd,
	    __USER_CAP_STR(uap->filename), uap->attrnamespace,
	    __USER_CAP_STR(uap->attrname)));
}

int
freebsd64_extattr_set_fd(struct thread *td,
    struct freebsd64_extattr_set_fd_args *uap)
{

	return (kern_extattr_set_fd(td, uap->fd, uap->attrnamespace,
	    __USER_CAP_STR(uap->attrname), __USER_CAP(uap->data, uap->nbytes),
	    uap->nbytes));
}

int
freebsd64_extattr_set_file(struct thread *td,
    struct freebsd64_extattr_set_file_args *uap)
{

	return (kern_extattr_set_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes, FOLLOW));
}

int
freebsd64_extattr_set_link(struct thread *td,
    struct freebsd64_extattr_set_link_args *uap)
{

	return (kern_extattr_set_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes, NOFOLLOW));
}

int
freebsd64_extattr_get_fd(struct thread *td,
    struct freebsd64_extattr_get_fd_args *uap)
{

	return (kern_extattr_get_fd(td, uap->fd, uap->attrnamespace,
	    __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes));
}

int
freebsd64_extattr_get_file(struct thread *td,
    struct freebsd64_extattr_get_file_args *uap)
{

	return (kern_extattr_get_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes, FOLLOW));
}

int
freebsd64_extattr_get_link(struct thread *td,
    struct freebsd64_extattr_get_link_args *uap)
{

	return (kern_extattr_get_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes, NOFOLLOW));
}

int
freebsd64_extattr_delete_fd(struct thread *td,
    struct freebsd64_extattr_delete_fd_args *uap)
{

	return (kern_extattr_delete_fd(td, uap->fd, uap->attrnamespace,
	    __USER_CAP_STR(uap->attrname)));
}

int
freebsd64_extattr_delete_file(struct thread *td,
    struct freebsd64_extattr_delete_file_args *uap)
{

	return (kern_extattr_delete_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname), FOLLOW));
}

int
freebsd64_extattr_delete_link(struct thread *td,
    struct freebsd64_extattr_delete_link_args *uap)
{

	return (kern_extattr_delete_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname), NOFOLLOW));
}

int
freebsd64_extattr_list_fd(struct thread *td,
    struct freebsd64_extattr_list_fd_args *uap)
{

	return (kern_extattr_list_fd(td, uap->fd, uap->attrnamespace,
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes));
}

int
freebsd64_extattr_list_file(struct thread *td,
    struct freebsd64_extattr_list_file_args *uap)
{

	return (kern_extattr_list_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP(uap->data, uap->nbytes),
	    uap->nbytes, FOLLOW));
}

int
freebsd64_extattr_list_link(struct thread *td,
    struct freebsd64_extattr_list_link_args *uap)
{

	return (kern_extattr_list_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP(uap->data, uap->nbytes),
	    uap->nbytes, NOFOLLOW));
}

/*
 * vfs_syscalls.c
 */
int
freebsd64_quotactl(struct thread *td, struct freebsd64_quotactl_args *uap)
{

	return (kern_quotactl(td, __USER_CAP_STR(uap->path),
	    uap->cmd, uap->uid, __USER_CAP_UNBOUND(uap->arg)));
}

int
freebsd64_statfs(struct thread *td, struct freebsd64_statfs_args *uap)
{

	return (user_statfs(td, __USER_CAP_STR(uap->path),
	    __USER_CAP_OBJ(uap->buf)));
}

int
freebsd64_fstatfs(struct thread *td, struct freebsd64_fstatfs_args *uap)
{

	return (user_fstatfs(td, uap->fd, __USER_CAP_OBJ(uap->buf)));
}

int
freebsd64_getfsstat(struct thread *td, struct freebsd64_getfsstat_args *uap)
{

	return (user_getfsstat(td, __USER_CAP(uap->buf, uap->bufsize),
	    uap->bufsize, uap->mode));
}

int
freebsd64_chdir(struct thread *td, struct freebsd64_chdir_args *uap)
{

	return (kern_chdir(td, __USER_CAP_STR(uap->path), UIO_USERSPACE));
}

int
freebsd64_chroot(struct thread *td, struct freebsd64_chroot_args *uap)
{

	return (kern_chroot(td, __USER_CAP_STR(uap->path)));
}

int
freebsd64_open(struct thread *td, struct freebsd64_open_args *uap)
{

	return (kern_openat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flags, uap->mode));
}

int
freebsd64_openat(struct thread *td, struct freebsd64_openat_args *uap)
{

	return (kern_openat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flag, uap->mode));
}


int
freebsd64_mknodat(struct thread *td, struct freebsd64_mknodat_args *uap)
{

	return (kern_mknodat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, uap->dev));
}

int
freebsd64_mkfifo(struct thread *td, struct freebsd64_mkfifo_args *uap)
{

	return (kern_mkfifoat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode));
}

int
freebsd64_mkfifoat(struct thread *td, struct freebsd64_mkfifoat_args *uap)
{

	return (kern_mkfifoat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode));
}

int
freebsd64_link(struct thread *td, struct freebsd64_link_args *uap)
{

	return (kern_linkat(td, AT_FDCWD, AT_FDCWD, __USER_CAP_STR(uap->path),
	    __USER_CAP_STR(uap->to), UIO_USERSPACE, FOLLOW));
}

int
freebsd64_linkat(struct thread *td, struct freebsd64_linkat_args *uap)
{
	int flag;

	flag = uap->flag;
	if (flag & ~AT_SYMLINK_FOLLOW)
		return (EINVAL);

	return (kern_linkat(td, uap->fd1, uap->fd2, __USER_CAP_STR(uap->path1),
	    __USER_CAP_STR(uap->path2), UIO_USERSPACE,
	    (flag & AT_SYMLINK_FOLLOW) ? FOLLOW : NOFOLLOW));
}

int
freebsd64_symlink(struct thread *td, struct freebsd64_symlink_args *uap)
{

	return (kern_symlinkat(td, __USER_CAP_STR(uap->path), AT_FDCWD,
	    __USER_CAP_STR(uap->link), UIO_USERSPACE));
}

int
freebsd64_symlinkat(struct thread *td, struct freebsd64_symlinkat_args *uap)
{

	return (kern_symlinkat(td, __USER_CAP_STR(uap->path1), uap->fd,
	    __USER_CAP_STR(uap->path2), UIO_USERSPACE));
}

int
freebsd64_undelete(struct thread *td, struct freebsd64_undelete_args *uap)
{

	return (kern_undelete(td, __USER_CAP_STR(uap->path), UIO_USERSPACE));
}

int
freebsd64_unlink(struct thread *td, struct freebsd64_unlink_args *uap)
{

	return (kern_funlinkat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    FD_NONE, UIO_USERSPACE, 0, 0));
}

int
freebsd64_unlinkat(struct thread *td, struct freebsd64_unlinkat_args *uap)
{

	return (kern_funlinkat_ex(td, uap->fd, __USER_CAP_STR(uap->path),
	    FD_NONE, uap->flag, UIO_USERSPACE, 0));
}

int
freebsd64_funlinkat(struct thread *td, struct freebsd64_funlinkat_args *uap)
{

	return (kern_funlinkat_ex(td, uap->dfd, __USER_CAP_STR(uap->path),
	    uap->fd, uap->flag, UIO_USERSPACE, 0));
}

int
freebsd64_access(struct thread *td, struct freebsd64_access_args *uap)
{

	return (kern_accessat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, 0, uap->amode));
}

int
freebsd64_faccessat(struct thread *td, struct freebsd64_faccessat_args *uap)
{

	return (kern_accessat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flag, uap->amode));
}

int
freebsd64_eaccess(struct thread *td, struct freebsd64_eaccess_args *uap)
{

	return (kern_accessat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, AT_EACCESS, uap->amode));
}

int
freebsd64_fstatat(struct thread *td, struct freebsd64_fstatat_args *uap)
{

	return (user_fstatat(td, uap->fd, __USER_CAP_STR(uap->path),
	    __USER_CAP_OBJ(uap->buf), uap->flag));
}

int
freebsd64_pathconf(struct thread *td, struct freebsd64_pathconf_args *uap)
{
	long value;
	int error;

	error = kern_pathconf(td, __USER_CAP_STR(uap->path), UIO_USERSPACE,
	    uap->name, FOLLOW, &value);
	if (error == 0)
		td->td_retval[0] = value;
	return (error);
}

int
freebsd64_lpathconf(struct thread *td, struct freebsd64_lpathconf_args *uap)
{
	long value;
	int error;

	error = kern_pathconf(td, __USER_CAP_STR(uap->path), UIO_USERSPACE,
	    uap->name, NOFOLLOW, &value);
	if (error == 0)
		td->td_retval[0] = value;
	return (error);
}

int
freebsd64_readlink(struct thread *td, struct freebsd64_readlink_args *uap)
{

	return (kern_readlinkat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP(uap->buf, uap->count), UIO_USERSPACE,
	    uap->count));
}

int
freebsd64_readlinkat(struct thread *td, struct freebsd64_readlinkat_args *uap)
{

	return (kern_readlinkat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP(uap->buf, uap->bufsize), UIO_USERSPACE,
	    uap->bufsize));
}

int
freebsd64_chflags(struct thread *td, struct freebsd64_chflags_args *uap)
{

	return (kern_chflagsat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flags, 0));
}

int
freebsd64_chflagsat(struct thread *td, struct freebsd64_chflagsat_args *uap)
{

	if (uap->atflag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (kern_chflagsat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flags, uap->atflag));
}

int
freebsd64_lchflags(struct thread *td, struct freebsd64_lchflags_args *uap)
{

	return (kern_chflagsat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flags, AT_SYMLINK_NOFOLLOW));
}

int
freebsd64_chmod(struct thread *td, struct freebsd64_chmod_args *uap)
{

	return (kern_fchmodat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, 0));
}

int
freebsd64_fchmodat(struct thread *td, struct freebsd64_fchmodat_args *uap)
{

	if (uap->flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (kern_fchmodat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, uap->flag));
}

int
freebsd64_lchmod(struct thread *td, struct freebsd64_lchmod_args *uap)
{

	return (kern_fchmodat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, AT_SYMLINK_NOFOLLOW));
}

int
freebsd64_chown(struct thread *td, struct freebsd64_chown_args *uap)
{

	return (kern_fchownat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->uid, uap->gid, 0));
}

int
freebsd64_fchownat(struct thread *td, struct freebsd64_fchownat_args *uap)
{

	return (kern_fchownat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->uid, uap->gid, uap->flag));
}

int
freebsd64_lchown(struct thread *td, struct freebsd64_lchown_args *uap)
{

	return (kern_fchownat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->uid, uap->gid, AT_SYMLINK_NOFOLLOW));
}

int
freebsd64_utimes(struct thread *td, struct freebsd64_utimes_args *uap)
{

	return (kern_utimesat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->tptr), UIO_USERSPACE));
}

int
freebsd64_futimesat(struct thread *td, struct freebsd64_futimesat_args *uap)
{

	return (kern_utimesat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->times), UIO_USERSPACE));
}

int
freebsd64_futimes(struct thread *td, struct freebsd64_futimes_args *uap)
{

	return (kern_futimes(td, uap->fd, __USER_CAP_OBJ(uap->tptr),
	    UIO_USERSPACE));
}


int
freebsd64_lutimes(struct thread *td, struct freebsd64_lutimes_args *uap)
{
	return (kern_lutimes(td, __USER_CAP_OBJ(uap->path), UIO_USERSPACE,
	    __USER_CAP_OBJ(uap->tptr), UIO_USERSPACE));
}

int
freebsd64_futimens(struct thread *td, struct freebsd64_futimens_args *uap)
{
	return (kern_futimens(td, uap->fd, __USER_CAP_OBJ(uap->times),
	    UIO_USERSPACE));
}

int
freebsd64_utimensat(struct thread *td, struct freebsd64_utimensat_args *uap)
{

	return (kern_utimensat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->times), UIO_USERSPACE,
	    uap->flag));
}

int
freebsd64_truncate(struct thread *td, struct freebsd64_truncate_args *uap)
{

	return (kern_truncate(td, __USER_CAP_STR(uap->path), UIO_USERSPACE,
	    uap->length));
}

int
freebsd64_rename(struct thread *td, struct freebsd64_rename_args *uap)
{

	return (kern_renameat(td, AT_FDCWD, __USER_CAP_STR(uap->from),
	    AT_FDCWD, __USER_CAP_STR(uap->to), UIO_USERSPACE));
}

int
freebsd64_renameat(struct thread *td, struct freebsd64_renameat_args *uap)
{

	return (kern_renameat(td, uap->oldfd, __USER_CAP_STR(uap->old),
	    uap->newfd, __USER_CAP_STR(uap->new), UIO_USERSPACE));
}

int
freebsd64_mkdir(struct thread *td, struct freebsd64_mkdir_args *uap)
{

	return (kern_mkdirat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode));
}

int
freebsd64_mkdirat(struct thread *td, struct freebsd64_mkdirat_args *uap)
{

	return (kern_mkdirat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode));
}

int
freebsd64_rmdir(struct thread *td, struct freebsd64_rmdir_args *uap)
{

	return (kern_frmdirat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    FD_NONE, UIO_USERSPACE, 0));
}

int
freebsd64_getdirentries(struct thread *td,
    struct freebsd64_getdirentries_args *uap)
{

	return (user_getdirentries(td, uap->fd,
	    __USER_CAP(uap->buf, uap->count), uap->count,
	    __USER_CAP_OBJ(uap->basep)));
}

int
freebsd64_unmount(struct thread *td, struct freebsd64_unmount_args *uap)
{

	return (kern_unmount(td, __USER_CAP_STR(uap->path), uap->flags));
}

int
freebsd64_revoke(struct thread *td, struct freebsd64_revoke_args *uap)
{

	return (kern_revoke(td, __USER_CAP_STR(uap->path), UIO_USERSPACE));
}

int
freebsd64_lgetfh(struct thread *td, struct freebsd64_lgetfh_args *uap)
{

	return (kern_getfhat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD,
	    __USER_CAP_STR(uap->fname), UIO_USERSPACE,
	    __USER_CAP_OBJ(uap->fhp)));
}

int
freebsd64_getfh(struct thread *td, struct freebsd64_getfh_args *uap)
{

	return (kern_getfhat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD,
	    __USER_CAP_STR(uap->fname), UIO_USERSPACE,
	    __USER_CAP_OBJ(uap->fhp)));
}

int
freebsd64_getfhat(struct thread *td, struct freebsd64_getfhat_args *uap)
{

	if ((uap->flags & ~(AT_SYMLINK_NOFOLLOW | AT_BENEATH)) != 0)
		return (EINVAL);
	return (kern_getfhat(td, uap->flags, uap->fd,
	    __USER_CAP_STR(uap->path), UIO_SYSSPACE,
	    __USER_CAP_OBJ(uap->fhp)));
}

int
freebsd64_fhlink(struct thread *td, struct freebsd64_fhlink_args *uap)
{

	return (kern_fhlinkat(td, AT_FDCWD, __USER_CAP_STR(uap->to),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->fhp)));
}

int
freebsd64_fhlinkat(struct thread *td, struct freebsd64_fhlinkat_args *uap)
{

	return (kern_fhlinkat(td, uap->tofd, __USER_CAP_STR(uap->to),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->fhp)));
}

int
freebsd64_fhreadlink(struct thread *td, struct freebsd64_fhreadlink_args *uap)
{

	return (kern_fhreadlink(td, __USER_CAP_OBJ(uap->fhp),
	    __USER_CAP(uap->buf, uap->bufsize), uap->bufsize));
}

int
freebsd64_fhopen(struct thread *td, struct freebsd64_fhopen_args *uap)
{

	return (kern_fhopen(td, __USER_CAP_OBJ(uap->u_fhp), uap->flags));
}

int
freebsd64_fhstat(struct thread *td, struct freebsd64_fhstat_args *uap)
{

	return (user_fhstat(td, __USER_CAP_OBJ(uap->u_fhp),
	    __USER_CAP_OBJ(uap->sb)));
}

int
freebsd64_fhstatfs(struct thread *td, struct freebsd64_fhstatfs_args *uap)
{

	return (user_fhstatfs(td, __USER_CAP_OBJ(uap->u_fhp),
	    __USER_CAP_OBJ(uap->buf)));
}
