/*-
 * Copyright (c) 2016 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

static inline int
CHERIABI_SYS_cheriabi_ioctl_fill_uap(struct thread *td,
    struct cheriabi_ioctl_args *uap)
{
	void * __capability tmpcap;
	register_t reqperms, tag;
	int error;

	/* [0] int fd */
	cheriabi_fetch_syscall_arg(td, &tmpcap, 0, CHERIABI_SYS_cheriabi_ioctl_PTRMASK);
	uap->fd = cheri_getoffset(tmpcap);

	/* [1] u_long com */
	cheriabi_fetch_syscall_arg(td, &tmpcap, 1, CHERIABI_SYS_cheriabi_ioctl_PTRMASK);
	uap->com = cheri_getoffset(tmpcap);

	/* [2] _Inout_opt_ caddr_t data */
	cheriabi_fetch_syscall_arg(td, &tmpcap, 2, CHERIABI_SYS_cheriabi_ioctl_PTRMASK);
	if (uap->com & IOC_VOID) {
		tag = cheri_gettag(tmpcap);
		if (!tag)
			uap->data = (void *)cheri_getoffset(tmpcap);
		else
			return (EPROT);
	} else {
		reqperms = 0;
		if (uap->com & IOC_IN)
			reqperms |= CHERI_PERM_LOAD;
		if (uap->com & IOC_OUT)
			reqperms |= CHERI_PERM_STORE;
		if (ioctl_data_contains_pointers(uap->com)) {
			if (reqperms & CHERI_PERM_LOAD)
				reqperms |= CHERI_PERM_LOAD_CAP;
			if (reqperms & CHERI_PERM_STORE)
				reqperms |= CHERI_PERM_STORE_CAP;
		}

		/*
		 * XXX-BD: not sure about may_be_null=1 here, but lower
		 * levels will fail cleanly is it is a problem.
		 */
		error = cheriabi_cap_to_ptr((caddr_t *)&uap->data,
		    tmpcap, IOCPARM_LEN(uap->com), reqperms, 1);
		if (error != 0)
			return (error);
	}

	return (0);
}

static inline int
CHERIABI_SYS_fcntl_fill_uap(struct thread *td,
    struct fcntl_args *uap)
{
	void * __capability tmpcap;
	int error;

	/* [0] int fd */
	cheriabi_fetch_syscall_arg(td, &tmpcap, 0, CHERIABI_SYS_fcntl_PTRMASK);
	uap->fd = cheri_getoffset(tmpcap);

	/* [1] int cmd */
	cheriabi_fetch_syscall_arg(td, &tmpcap, 1, CHERIABI_SYS_fcntl_PTRMASK);
	uap->cmd = cheri_getoffset(tmpcap);

	/* [2] intptr_t arg */
	/*
	 * There are three cases.  arg is ignored, arg is an int, and arg
	 * is a pointer to struct flock.  We rely on userspace to have
	 * promoted integers to intptr_t so we're only dealing with a
	 * capability argument.
	 */
	switch (uap->cmd) {
	case F_GETFD:
	case F_GETFL:
	case F_GETOWN:
		uap->arg = (intptr_t)NULL;
		break;

	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
	case F_DUP2FD:
	case F_DUP2FD_CLOEXEC:
	case F_SETFD:
	case F_SETFL:
	case F_SETOWN:
	case F_READAHEAD:
	case F_RDAHEAD:
		cheriabi_fetch_syscall_arg(td, &tmpcap, 2, CHERIABI_SYS_fcntl_PTRMASK);
		uap->arg = cheri_getoffset(tmpcap);
		break;

	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
		cheriabi_fetch_syscall_arg(td, &tmpcap, 2, CHERIABI_SYS_fcntl_PTRMASK);
		error = cheriabi_cap_to_ptr((caddr_t *)&uap->arg,
		    tmpcap, sizeof(struct flock), CHERI_PERM_LOAD, 0);
		if (error != 0)
			return (error);
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

static inline int
CHERIABI_SYS_cheriabi_sysarch_fill_uap(struct thread *td,
    struct cheriabi_sysarch_args *uap)
{
	void * __capability tmpcap;

	/* [0] int op */
	cheriabi_fetch_syscall_arg(td, &tmpcap, 0, CHERIABI_SYS_cheriabi_sysarch_PTRMASK);
	uap->op = cheri_getoffset(tmpcap);

	/* [1] char * parms */
	/*
	 * parms could be basically anything and sysarch is fundamentally
	 * machine dependant.  Punt all the duty of checking and
	 * handling parms to the MD cheriabi_sysarch.  This is safe enough
	 * because if porter's fail to do the work, they will end up with
	 * NULL in uap->parms.
	 */
	uap->parms = NULL;

	return (0);
}

#include <sys/umtx.h>

static inline int
CHERIABI_SYS__umtx_op_fill_uap(struct thread *td,
    struct _umtx_op_args *uap)
{
	void * __capability tmpcap;
	int error;
	register_t reqperms, tag;
	size_t reqsize;

	/* [1] int op */
	cheriabi_fetch_syscall_arg(td, &tmpcap, 1, CHERIABI_SYS__umtx_op_PTRMASK);
	uap->op = cheri_getoffset(tmpcap);

	/* Short cut, blocking known unimplemted ops */
	switch (uap->op) {
	case UMTX_OP_RESERVED0:			/* __umtx_op_unimpl */
	case UMTX_OP_RESERVED1:			/* __umtx_op_unimpl */
	case UMTX_OP_SEM_WAIT:			/* __umtx_op_unimpl */
	case UMTX_OP_SEM_WAKE:			/* __umtx_op_unimpl */
		return (EOPNOTSUPP);
	}

	/* [2] u_long val */
	cheriabi_fetch_syscall_arg(td, &tmpcap, 2, CHERIABI_SYS__umtx_op_PTRMASK);
	uap->val = cheri_getoffset(tmpcap);

	/* [0] void * obj */
	reqperms = 0;
	switch (uap->op) {
	case UMTX_OP_WAIT:			/* __umtx_op_wait */
	case UMTX_OP_WAKE:			/* __umtx_op_wake */
	case UMTX_OP_WAKE_PRIVATE: 		/* __umtx_op_wake_private */
		reqsize = sizeof(u_long);
		reqperms |= CHERI_PERM_LOAD;
		break;

	case UMTX_OP_MUTEX_TRYLOCK:		/* __umtx_op_trylock_umutex */
	case UMTX_OP_MUTEX_LOCK:		/* __umtx_op_lock_umutex */
	case UMTX_OP_MUTEX_UNLOCK: 		/* __umtx_op_unlock_umutex */
	case UMTX_OP_MUTEX_WAIT:		/* __umtx_op_wait_umutex */
	case UMTX_OP_MUTEX_WAKE:		/* __umtx_op_wake_umutex */
	case UMTX_OP_MUTEX_WAKE2:		/* __umtx_op_wake2_umutex */
	case UMTX_OP_SET_CEILING:		/* __umtx_op_set_ceiling */
		reqsize = sizeof(struct umutex);
		reqperms |= CHERI_PERM_LOAD|CHERI_PERM_STORE;
		break;

	case UMTX_OP_CV_WAIT:			/* __umtx_op_cv_wait */
	case UMTX_OP_CV_SIGNAL:			/* __umtx_op_cv_signal */
	case UMTX_OP_CV_BROADCAST:		/* __umtx_op_cv_broadcast */
		reqsize = sizeof(struct ucond);
		reqperms |= CHERI_PERM_LOAD|CHERI_PERM_STORE;
		break;

	case UMTX_OP_WAIT_UINT:			/* __umtx_op_wait_uint */
	case UMTX_OP_WAIT_UINT_PRIVATE:	/* __umtx_op_wait_uint_private */
		reqsize = sizeof(u_int);
		reqperms |= CHERI_PERM_LOAD;
		break;

	case UMTX_OP_RW_RDLOCK:			/* __umtx_op_rw_rdlock */
	case UMTX_OP_RW_WRLOCK:			/* __umtx_op_rw_wrlock */
	case UMTX_OP_RW_UNLOCK:			/* __umtx_op_rw_unlock */
		reqsize = sizeof(struct urwlock);
		reqperms |= CHERI_PERM_LOAD|CHERI_PERM_STORE;
		break;

	case UMTX_OP_NWAKE_PRIVATE:		/* __umtx_op_nwake_private */
		/* obj points to an array of (int*) with val elements. */
		reqsize = sizeof(tmpcap) * uap->val;
		reqperms |= CHERI_PERM_LOAD|CHERI_PERM_LOAD_CAP;
		break;

	case UMTX_OP_SEM2_WAIT:			/* __umtx_op_sem2_wait */
	case UMTX_OP_SEM2_WAKE:			/* __umtx_op_sem2_wake */
		reqsize = sizeof(struct _usem2);
		reqperms |= CHERI_PERM_LOAD|CHERI_PERM_STORE;
		break;

#ifdef UMTX_OP_SHM
	case UMTX_OP_SHM:			/* __umtx_op_shm */
		reqsize = 0; /* Expect NULL, obj is unused */
		break;
#endif

	default:
		return (EINVAL);
	}
	cheriabi_fetch_syscall_arg(td, &tmpcap, 0, CHERIABI_SYS__umtx_op_PTRMASK);
	error = cheriabi_cap_to_ptr((caddr_t *)&uap->obj, tmpcap,
	    reqsize, reqperms,
#ifdef UMTX_OP_SHM
	    (uap->op == UMTX_OP_SHM));
#else
	    0);
#endif
	if (error != 0)
		return (error);

	/* [3] void * uaddr1 */
	switch (uap->op) {
	case UMTX_OP_WAKE:			/* __umtx_op_wake */
	case UMTX_OP_MUTEX_TRYLOCK:		/* __umtx_op_trylock_umutex */
	case UMTX_OP_MUTEX_UNLOCK: 		/* __umtx_op_unlock_umutex */
	case UMTX_OP_CV_SIGNAL:			/* __umtx_op_cv_signal */
	case UMTX_OP_CV_BROADCAST:		/* __umtx_op_cv_broadcast */
	case UMTX_OP_RW_UNLOCK:			/* __umtx_op_rw_unlock */
	case UMTX_OP_WAKE_PRIVATE: 		/* __umtx_op_wake_private */
	case UMTX_OP_MUTEX_WAKE:		/* __umtx_op_wake_umutex */
	case UMTX_OP_NWAKE_PRIVATE:		/* __umtx_op_nwake_private */
	case UMTX_OP_MUTEX_WAKE2:		/* __umtx_op_wake2_umutex */
	case UMTX_OP_SEM2_WAKE:			/* __umtx_op_sem2_wake */
		/* uaddr1 and uaddr2 are ignored */
		uap->uaddr1 = NULL;
		uap->uaddr2 = NULL;
		return (0);

	case UMTX_OP_WAIT:			/* __umtx_op_wait */
	case UMTX_OP_MUTEX_LOCK:		/* __umtx_op_lock_umutex */
	case UMTX_OP_WAIT_UINT:			/* __umtx_op_wait_uint */
	case UMTX_OP_RW_RDLOCK:			/* __umtx_op_rw_rdlock */
	case UMTX_OP_RW_WRLOCK:			/* __umtx_op_rw_wrlock */
	case UMTX_OP_WAIT_UINT_PRIVATE:	/* __umtx_op_wait_uint_private */
	case UMTX_OP_MUTEX_WAIT:		/* __umtx_op_wait_umutex */
	case UMTX_OP_SEM2_WAIT:			/* __umtx_op_sem2_wait */
		/* uaddr1 is a size_t to pass to umtx_copyin_umtx_time() */
		cheriabi_fetch_syscall_arg(td, &tmpcap, 3, CHERIABI_SYS__umtx_op_PTRMASK);
		tag = cheri_gettag(tmpcap);
		if (!tag) {
			/*
			 * Follow the logic in umtx_copyin_umtx_time()
			 * and assume we'll copy in a struct timespec if
			 * the size is less than struct timespec.
			 */
			uap->uaddr1 = (void *)cheri_getoffset(tmpcap);
			if ((size_t)uap->uaddr1 <= sizeof(struct timespec))
				reqsize = sizeof(struct timespec);
			else
				reqsize = (size_t)uap->uaddr1;
		} else {
			/* Reject pointers */
			return (EPROT);
		}
		break;

	case UMTX_OP_SET_CEILING:		/* __umtx_op_set_ceiling */
		/*
		 * uaddr1 is a pointer to a writeable uint32_t and may be NULL
		 */
		cheriabi_fetch_syscall_arg(td, &tmpcap, 3, CHERIABI_SYS__umtx_op_PTRMASK);
		error = cheriabi_cap_to_ptr((caddr_t *)&uap->uaddr1, tmpcap,
		    sizeof(uint32_t), CHERI_PERM_STORE, 1);
		if (error != 0)
			return (error);
		/* uaddr2 is ignored */
		uap->uaddr2 = NULL;
		return (0);

	case UMTX_OP_CV_WAIT:			/* __umtx_op_cv_wait */
		cheriabi_fetch_syscall_arg(td, &tmpcap, 3, CHERIABI_SYS__umtx_op_PTRMASK);
		error = cheriabi_cap_to_ptr((caddr_t *)&uap->uaddr1, tmpcap,
		    sizeof(struct umutex), CHERI_PERM_STORE, 0);
		if (error != 0)
			return (error);
		/* uaddr2 is a struct timespec or NULL */
		reqsize = sizeof(struct timespec);
		break;

#ifdef NOTYET
#ifdef UMTX_OP_SHM
	case UMTX_OP_SHM:			/* __umtx_op_shm */
		/*
		 * uaddr1 is an address.  The access requirements depend
		 * on val.
		 */
		cheriabi_fetch_syscall_arg(td, &tmpcap, 3, CHERIABI_SYS__umtx_op_PTRMASK);
		tag = cheri_gettag(tmpcap);
		if (!tag) {
			return (EPROT);
		} else {
			sealed = cheri_getsealed(tmpcap);
			if (sealed)
				return (EPROT);

			perms = cheri_getperm(tmpcap);
			reqperms = CHERI_PERM_GLOBAL;
			if ((perms & reqperms) != reqperms)
				return (EPROT);

			/*
			 * XXX-BD: unclear what length is required and if
			 * length can be checked here and when must be
			 * checked in the syscall.
			 */

			uap->uaddr1 = tmpcap;
		}
		/*
		 * XXX-BD: not yet implemented.
		 */
		return (EOPNOTSUPP);

		/* uaddr2 is ignored */
		uap->uaddr2 = NULL;
		return (0);
#endif
#endif
	default:
		return (EINVAL);
	}

	/* [4] void * uaddr2 */
	/* Sanity check that only expected ops have made it this far */
	switch (uap->op) {
	case UMTX_OP_WAIT:			/* __umtx_op_wait */
	case UMTX_OP_MUTEX_LOCK:		/* __umtx_op_lock_umutex */
	case UMTX_OP_WAIT_UINT:			/* __umtx_op_wait_uint */
	case UMTX_OP_RW_RDLOCK:			/* __umtx_op_rw_rdlock */
	case UMTX_OP_RW_WRLOCK:			/* __umtx_op_rw_wrlock */
	case UMTX_OP_WAIT_UINT_PRIVATE:	/* __umtx_op_wait_uint_private */
	case UMTX_OP_MUTEX_WAIT:		/* __umtx_op_wait_umutex */
	case UMTX_OP_SEM2_WAIT:			/* __umtx_op_sem2_wait */
	case UMTX_OP_CV_WAIT:			/* __umtx_op_cv_wait */
		break;
	default:
		panic("%s: unexepected op made it to uaddr2 %d", __func__,
		    uap->op);
	}
	cheriabi_fetch_syscall_arg(td, &tmpcap, 4, CHERIABI_SYS__umtx_op_PTRMASK);
	error = cheriabi_cap_to_ptr((caddr_t *)&uap->uaddr2, tmpcap,
	    reqsize, reqperms, 1);
	if (error != 0)
		return (error);

	return (0);
}
