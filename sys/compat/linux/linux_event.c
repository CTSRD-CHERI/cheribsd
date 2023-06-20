/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2007 Roman Divacky
 * Copyright (c) 2014 Dmitry Chagin <dchagin@FreeBSD.org>
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
#include <sys/callout.h>
#include <sys/capsicum.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/selinfo.h>
#include <sys/specialfd.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/timespec.h>
#include <sys/user.h>

#ifdef COMPAT_LINUX32
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>
#endif

#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_event.h>
#include <compat/linux/linux_file.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_time.h>
#include <compat/linux/linux_util.h>

typedef uint64_t	epoll_udata_t;

struct epoll_event {
	uint32_t	events;
	epoll_udata_t	data;
}
#if defined(__amd64__)
__attribute__((packed))
#endif
;

#define	LINUX_MAX_EVENTS	(INT_MAX / sizeof(struct epoll_event))

static int	epoll_to_kevent(struct thread *td, int fd,
		    struct epoll_event *l_event, struct kevent *kevent,
		    int *nkevents);
static void	kevent_to_epoll(struct kevent *kevent, struct epoll_event *l_event);
static int	epoll_kev_copyout(void *arg, struct kevent *kevp, int count);
static int	epoll_kev_copyin(void *arg, struct kevent *kevp, int count);
static int	epoll_register_kevent(struct thread *td, struct file *epfp,
		    int fd, int filter, unsigned int flags);
static int	epoll_fd_registered(struct thread *td, struct file *epfp,
		    int fd);
static int	epoll_delete_all_events(struct thread *td, struct file *epfp,
		    int fd);

struct epoll_copyin_args {
	struct kevent	*changelist;
};

struct epoll_copyout_args {
	struct epoll_event	*leventlist;
	struct proc		*p;
	uint32_t		count;
	int			error;
};

/* timerfd */
typedef uint64_t	timerfd_t;

static fo_rdwr_t	timerfd_read;
static fo_ioctl_t	timerfd_ioctl;
static fo_poll_t	timerfd_poll;
static fo_kqfilter_t	timerfd_kqfilter;
static fo_stat_t	timerfd_stat;
static fo_close_t	timerfd_close;
static fo_fill_kinfo_t	timerfd_fill_kinfo;

static struct fileops timerfdops = {
	.fo_read = timerfd_read,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = timerfd_ioctl,
	.fo_poll = timerfd_poll,
	.fo_kqfilter = timerfd_kqfilter,
	.fo_stat = timerfd_stat,
	.fo_close = timerfd_close,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_fill_kinfo = timerfd_fill_kinfo,
	.fo_flags = DFLAG_PASSABLE
};

static void	filt_timerfddetach(struct knote *kn);
static int	filt_timerfdread(struct knote *kn, long hint);

static struct filterops timerfd_rfiltops = {
	.f_isfd = 1,
	.f_detach = filt_timerfddetach,
	.f_event = filt_timerfdread
};

struct timerfd {
	clockid_t	tfd_clockid;
	struct itimerspec tfd_time;
	struct callout	tfd_callout;
	timerfd_t	tfd_count;
	bool		tfd_canceled;
	struct selinfo	tfd_sel;
	struct mtx	tfd_lock;
};

static void	linux_timerfd_expire(void *);
static void	linux_timerfd_curval(struct timerfd *, struct itimerspec *);

static int
epoll_create_common(struct thread *td, int flags)
{

	return (kern_kqueue(td, flags, NULL));
}

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_epoll_create(struct thread *td, struct linux_epoll_create_args *args)
{

	/*
	 * args->size is unused. Linux just tests it
	 * and then forgets it as well.
	 */
	if (args->size <= 0)
		return (EINVAL);

	return (epoll_create_common(td, 0));
}
#endif

int
linux_epoll_create1(struct thread *td, struct linux_epoll_create1_args *args)
{
	int flags;

	if ((args->flags & ~(LINUX_O_CLOEXEC)) != 0)
		return (EINVAL);

	flags = 0;
	if ((args->flags & LINUX_O_CLOEXEC) != 0)
		flags |= O_CLOEXEC;

	return (epoll_create_common(td, flags));
}

/* Structure converting function from epoll to kevent. */
static int
epoll_to_kevent(struct thread *td, int fd, struct epoll_event *l_event,
    struct kevent *kevent, int *nkevents)
{
	uint32_t levents = l_event->events;
	struct linux_pemuldata *pem;
	struct proc *p;
	unsigned short kev_flags = EV_ADD | EV_ENABLE;

	/* flags related to how event is registered */
	if ((levents & LINUX_EPOLLONESHOT) != 0)
		kev_flags |= EV_DISPATCH;
	if ((levents & LINUX_EPOLLET) != 0)
		kev_flags |= EV_CLEAR;
	if ((levents & LINUX_EPOLLERR) != 0)
		kev_flags |= EV_ERROR;
	if ((levents & LINUX_EPOLLRDHUP) != 0)
		kev_flags |= EV_EOF;

	/* flags related to what event is registered */
	if ((levents & LINUX_EPOLL_EVRD) != 0) {
		EV_SET(kevent, fd, EVFILT_READ, kev_flags, 0, 0, 0);
		kevent->ext[0] = l_event->data;
		++kevent;
		++(*nkevents);
	}
	if ((levents & LINUX_EPOLL_EVWR) != 0) {
		EV_SET(kevent, fd, EVFILT_WRITE, kev_flags, 0, 0, 0);
		kevent->ext[0] = l_event->data;
		++kevent;
		++(*nkevents);
	}
	/* zero event mask is legal */
	if ((levents & (LINUX_EPOLL_EVRD | LINUX_EPOLL_EVWR)) == 0) {
		EV_SET(kevent++, fd, EVFILT_READ, EV_ADD|EV_DISABLE, 0, 0, 0);
		++(*nkevents);
	}

	if ((levents & ~(LINUX_EPOLL_EVSUP)) != 0) {
		p = td->td_proc;

		pem = pem_find(p);
		KASSERT(pem != NULL, ("epoll proc emuldata not found.\n"));

		LINUX_PEM_XLOCK(pem);
		if ((pem->flags & LINUX_XUNSUP_EPOLL) == 0) {
			pem->flags |= LINUX_XUNSUP_EPOLL;
			LINUX_PEM_XUNLOCK(pem);
			linux_msg(td, "epoll_ctl unsupported flags: 0x%x",
			    levents);
		} else
			LINUX_PEM_XUNLOCK(pem);
		return (EINVAL);
	}

	return (0);
}

/*
 * Structure converting function from kevent to epoll. In a case
 * this is called on error in registration we store the error in
 * event->data and pick it up later in linux_epoll_ctl().
 */
static void
kevent_to_epoll(struct kevent *kevent, struct epoll_event *l_event)
{

	l_event->data = kevent->ext[0];

	if ((kevent->flags & EV_ERROR) != 0) {
		l_event->events = LINUX_EPOLLERR;
		return;
	}

	/* XXX EPOLLPRI, EPOLLHUP */
	switch (kevent->filter) {
	case EVFILT_READ:
		l_event->events = LINUX_EPOLLIN;
		if ((kevent->flags & EV_EOF) != 0)
			l_event->events |= LINUX_EPOLLRDHUP;
	break;
	case EVFILT_WRITE:
		l_event->events = LINUX_EPOLLOUT;
	break;
	}
}

/*
 * Copyout callback used by kevent. This converts kevent
 * events to epoll events and copies them back to the
 * userspace. This is also called on error on registering
 * of the filter.
 */
static int
epoll_kev_copyout(void *arg, struct kevent *kevp, int count)
{
	struct epoll_copyout_args *args;
	struct epoll_event *eep;
	int error, i;

	args = (struct epoll_copyout_args*) arg;
	eep = malloc(sizeof(*eep) * count, M_EPOLL, M_WAITOK | M_ZERO);

	for (i = 0; i < count; i++)
		kevent_to_epoll(&kevp[i], &eep[i]);

	error = copyout(eep, args->leventlist, count * sizeof(*eep));
	if (error == 0) {
		args->leventlist += count;
		args->count += count;
	} else if (args->error == 0)
		args->error = error;

	free(eep, M_EPOLL);
	return (error);
}

/*
 * Copyin callback used by kevent. This copies already
 * converted filters from kernel memory to the kevent
 * internal kernel memory. Hence the memcpy instead of
 * copyin.
 */
static int
epoll_kev_copyin(void *arg, struct kevent *kevp, int count)
{
	struct epoll_copyin_args *args;

	args = (struct epoll_copyin_args*) arg;

	memcpy(kevp, args->changelist, count * sizeof(*kevp));
	args->changelist += count;

	return (0);
}

/*
 * Load epoll filter, convert it to kevent filter
 * and load it into kevent subsystem.
 */
int
linux_epoll_ctl(struct thread *td, struct linux_epoll_ctl_args *args)
{
	struct file *epfp, *fp;
	struct epoll_copyin_args ciargs;
	struct kevent kev[2];
	struct kevent_copyops k_ops = { &ciargs,
					NULL,
					epoll_kev_copyin};
	struct epoll_event le;
	cap_rights_t rights;
	int nchanges = 0;
	int error;

	if (args->op != LINUX_EPOLL_CTL_DEL) {
		error = copyin(args->event, &le, sizeof(le));
		if (error != 0)
			return (error);
	}

	error = fget(td, args->epfd,
	    cap_rights_init_one(&rights, CAP_KQUEUE_CHANGE), &epfp);
	if (error != 0)
		return (error);
	if (epfp->f_type != DTYPE_KQUEUE) {
		error = EINVAL;
		goto leave1;
	}

	 /* Protect user data vector from incorrectly supplied fd. */
	error = fget(td, args->fd,
		     cap_rights_init_one(&rights, CAP_POLL_EVENT), &fp);
	if (error != 0)
		goto leave1;

	/* Linux disallows spying on himself */
	if (epfp == fp) {
		error = EINVAL;
		goto leave0;
	}

	ciargs.changelist = kev;

	if (args->op != LINUX_EPOLL_CTL_DEL) {
		error = epoll_to_kevent(td, args->fd, &le, kev, &nchanges);
		if (error != 0)
			goto leave0;
	}

	switch (args->op) {
	case LINUX_EPOLL_CTL_MOD:
		error = epoll_delete_all_events(td, epfp, args->fd);
		if (error != 0)
			goto leave0;
		break;

	case LINUX_EPOLL_CTL_ADD:
		if (epoll_fd_registered(td, epfp, args->fd)) {
			error = EEXIST;
			goto leave0;
		}
		break;

	case LINUX_EPOLL_CTL_DEL:
		/* CTL_DEL means unregister this fd with this epoll */
		error = epoll_delete_all_events(td, epfp, args->fd);
		goto leave0;

	default:
		error = EINVAL;
		goto leave0;
	}

	error = kern_kevent_fp(td, epfp, nchanges, 0, &k_ops, NULL);

leave0:
	fdrop(fp, td);

leave1:
	fdrop(epfp, td);
	return (error);
}

/*
 * Wait for a filter to be triggered on the epoll file descriptor.
 */

static int
linux_epoll_wait_ts(struct thread *td, int epfd, struct epoll_event *events,
    int maxevents, struct timespec *tsp, sigset_t *uset)
{
	struct epoll_copyout_args coargs;
	struct kevent_copyops k_ops = { &coargs,
					epoll_kev_copyout,
					NULL};
	cap_rights_t rights;
	struct file *epfp;
	sigset_t omask;
	int error;

	if (maxevents <= 0 || maxevents > LINUX_MAX_EVENTS)
		return (EINVAL);

	error = fget(td, epfd,
	    cap_rights_init_one(&rights, CAP_KQUEUE_EVENT), &epfp);
	if (error != 0)
		return (error);
	if (epfp->f_type != DTYPE_KQUEUE) {
		error = EINVAL;
		goto leave;
	}
	if (uset != NULL) {
		error = kern_sigprocmask(td, SIG_SETMASK, uset,
		    &omask, 0);
		if (error != 0)
			goto leave;
		td->td_pflags |= TDP_OLDMASK;
		/*
		 * Make sure that ast() is called on return to
		 * usermode and TDP_OLDMASK is cleared, restoring old
		 * sigmask.
		 */
		ast_sched(td, TDA_SIGSUSPEND);
	}

	coargs.leventlist = events;
	coargs.p = td->td_proc;
	coargs.count = 0;
	coargs.error = 0;

	error = kern_kevent_fp(td, epfp, 0, maxevents, &k_ops, tsp);
	if (error == 0 && coargs.error != 0)
		error = coargs.error;

	/*
	 * kern_kevent might return ENOMEM which is not expected from epoll_wait.
	 * Maybe we should translate that but I don't think it matters at all.
	 */
	if (error == 0)
		td->td_retval[0] = coargs.count;

	if (uset != NULL)
		error = kern_sigprocmask(td, SIG_SETMASK, &omask,
		    NULL, 0);
leave:
	fdrop(epfp, td);
	return (error);
}

static int
linux_epoll_wait_common(struct thread *td, int epfd, struct epoll_event *events,
    int maxevents, int timeout, sigset_t *uset)
{
	struct timespec ts, *tsp;

	/*
	 * Linux epoll_wait(2) man page states that timeout of -1 causes caller
	 * to block indefinitely. Real implementation does it if any negative
	 * timeout value is passed.
	 */
	if (timeout >= 0) {
		/* Convert from milliseconds to timespec. */
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	} else {
		tsp = NULL;
	}
	return (linux_epoll_wait_ts(td, epfd, events, maxevents, tsp, uset));

}

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_epoll_wait(struct thread *td, struct linux_epoll_wait_args *args)
{

	return (linux_epoll_wait_common(td, args->epfd, args->events,
	    args->maxevents, args->timeout, NULL));
}
#endif

int
linux_epoll_pwait(struct thread *td, struct linux_epoll_pwait_args *args)
{
	sigset_t mask, *pmask;
	int error;

	error = linux_copyin_sigset(td, args->mask, sizeof(l_sigset_t),
	    &mask, &pmask);
	if (error != 0)
		return (error);

	return (linux_epoll_wait_common(td, args->epfd, args->events,
	    args->maxevents, args->timeout, pmask));
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_epoll_pwait2_64(struct thread *td, struct linux_epoll_pwait2_64_args *args)
{
	struct timespec ts, *tsa;
	sigset_t mask, *pmask;
	int error;

	error = linux_copyin_sigset(td, args->mask, sizeof(l_sigset_t),
	    &mask, &pmask);
	if (error != 0)
		return (error);

	if (args->timeout) {
		error = linux_get_timespec64(&ts, args->timeout);
		if (error != 0)
			return (error);
		tsa = &ts;
	} else
		tsa = NULL;

	return (linux_epoll_wait_ts(td, args->epfd, args->events,
	    args->maxevents, tsa, pmask));
}
#else
int
linux_epoll_pwait2(struct thread *td, struct linux_epoll_pwait2_args *args)
{
	struct timespec ts, *tsa;
	sigset_t mask, *pmask;
	int error;

	error = linux_copyin_sigset(td, args->mask, sizeof(l_sigset_t),
	    &mask, &pmask);
	if (error != 0)
		return (error);

	if (args->timeout) {
		error = linux_get_timespec(&ts, args->timeout);
		if (error != 0)
			return (error);
		tsa = &ts;
	} else
		tsa = NULL;

	return (linux_epoll_wait_ts(td, args->epfd, args->events,
	    args->maxevents, tsa, pmask));
}
#endif /* __i386__ || (__amd64__ && COMPAT_LINUX32) */

static int
epoll_register_kevent(struct thread *td, struct file *epfp, int fd, int filter,
    unsigned int flags)
{
	struct epoll_copyin_args ciargs;
	struct kevent kev;
	struct kevent_copyops k_ops = { &ciargs,
					NULL,
					epoll_kev_copyin};

	ciargs.changelist = &kev;
	EV_SET(&kev, fd, filter, flags, 0, 0, 0);

	return (kern_kevent_fp(td, epfp, 1, 0, &k_ops, NULL));
}

static int
epoll_fd_registered(struct thread *td, struct file *epfp, int fd)
{
	/*
	 * Set empty filter flags to avoid accidental modification of already
	 * registered events. In the case of event re-registration:
	 * 1. If event does not exists kevent() does nothing and returns ENOENT
	 * 2. If event does exists, it's enabled/disabled state is preserved
	 *    but fflags, data and udata fields are overwritten. So we can not
	 *    set socket lowats and store user's context pointer in udata.
	 */
	if (epoll_register_kevent(td, epfp, fd, EVFILT_READ, 0) != ENOENT ||
	    epoll_register_kevent(td, epfp, fd, EVFILT_WRITE, 0) != ENOENT)
		return (1);

	return (0);
}

static int
epoll_delete_all_events(struct thread *td, struct file *epfp, int fd)
{
	int error1, error2;

	error1 = epoll_register_kevent(td, epfp, fd, EVFILT_READ, EV_DELETE);
	error2 = epoll_register_kevent(td, epfp, fd, EVFILT_WRITE, EV_DELETE);

	/* return 0 if at least one result positive */
	return (error1 == 0 ? 0 : error2);
}

#ifdef LINUX_LEGACY_SYSCALLS
int
linux_eventfd(struct thread *td, struct linux_eventfd_args *args)
{
	struct specialfd_eventfd ae;

	bzero(&ae, sizeof(ae));
	ae.initval = args->initval;
	return (kern_specialfd(td, SPECIALFD_EVENTFD, &ae));
}
#endif

int
linux_eventfd2(struct thread *td, struct linux_eventfd2_args *args)
{
	struct specialfd_eventfd ae;
	int flags;

	if ((args->flags & ~(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK |
	    LINUX_EFD_SEMAPHORE)) != 0)
		return (EINVAL);
	flags = 0;
	if ((args->flags & LINUX_O_CLOEXEC) != 0)
		flags |= EFD_CLOEXEC;
	if ((args->flags & LINUX_O_NONBLOCK) != 0)
		flags |= EFD_NONBLOCK;
	if ((args->flags & LINUX_EFD_SEMAPHORE) != 0)
		flags |= EFD_SEMAPHORE;

	bzero(&ae, sizeof(ae));
	ae.flags = flags;
	ae.initval = args->initval;
	return (kern_specialfd(td, SPECIALFD_EVENTFD, &ae));
}

int
linux_timerfd_create(struct thread *td, struct linux_timerfd_create_args *args)
{
	struct timerfd *tfd;
	struct file *fp;
	clockid_t clockid;
	int fflags, fd, error;

	if ((args->flags & ~LINUX_TFD_CREATE_FLAGS) != 0)
		return (EINVAL);

	error = linux_to_native_clockid(&clockid, args->clockid);
	if (error != 0)
		return (error);
	if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC)
		return (EINVAL);

	fflags = 0;
	if ((args->flags & LINUX_TFD_CLOEXEC) != 0)
		fflags |= O_CLOEXEC;

	error = falloc(td, &fp, &fd, fflags);
	if (error != 0)
		return (error);

	tfd = malloc(sizeof(*tfd), M_EPOLL, M_WAITOK | M_ZERO);
	tfd->tfd_clockid = clockid;
	mtx_init(&tfd->tfd_lock, "timerfd", NULL, MTX_DEF);

	callout_init_mtx(&tfd->tfd_callout, &tfd->tfd_lock, 0);
	knlist_init_mtx(&tfd->tfd_sel.si_note, &tfd->tfd_lock);

	fflags = FREAD;
	if ((args->flags & LINUX_O_NONBLOCK) != 0)
		fflags |= FNONBLOCK;

	finit(fp, fflags, DTYPE_LINUXTFD, tfd, &timerfdops);
	fdrop(fp, td);

	td->td_retval[0] = fd;
	return (error);
}

static int
timerfd_close(struct file *fp, struct thread *td)
{
	struct timerfd *tfd;

	tfd = fp->f_data;
	if (fp->f_type != DTYPE_LINUXTFD || tfd == NULL)
		return (EINVAL);

	timespecclear(&tfd->tfd_time.it_value);
	timespecclear(&tfd->tfd_time.it_interval);

	callout_drain(&tfd->tfd_callout);

	seldrain(&tfd->tfd_sel);
	knlist_destroy(&tfd->tfd_sel.si_note);

	fp->f_ops = &badfileops;
	mtx_destroy(&tfd->tfd_lock);
	free(tfd, M_EPOLL);

	return (0);
}

static int
timerfd_read(struct file *fp, struct uio *uio, struct ucred *active_cred,
    int flags, struct thread *td)
{
	struct timerfd *tfd;
	timerfd_t count;
	int error;

	tfd = fp->f_data;
	if (fp->f_type != DTYPE_LINUXTFD || tfd == NULL)
		return (EINVAL);

	if (uio->uio_resid < sizeof(timerfd_t))
		return (EINVAL);

	error = 0;
	mtx_lock(&tfd->tfd_lock);
retry:
	if (tfd->tfd_canceled) {
		tfd->tfd_count = 0;
		mtx_unlock(&tfd->tfd_lock);
		return (ECANCELED);
	}
	if (tfd->tfd_count == 0) {
		if ((fp->f_flag & FNONBLOCK) != 0) {
			mtx_unlock(&tfd->tfd_lock);
			return (EAGAIN);
		}
		error = mtx_sleep(&tfd->tfd_count, &tfd->tfd_lock, PCATCH, "ltfdrd", 0);
		if (error == 0)
			goto retry;
	}
	if (error == 0) {
		count = tfd->tfd_count;
		tfd->tfd_count = 0;
		mtx_unlock(&tfd->tfd_lock);
		error = uiomove(&count, sizeof(timerfd_t), uio);
	} else
		mtx_unlock(&tfd->tfd_lock);

	return (error);
}

static int
timerfd_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct timerfd *tfd;
	int revents = 0;

	tfd = fp->f_data;
	if (fp->f_type != DTYPE_LINUXTFD || tfd == NULL)
		return (POLLERR);

	mtx_lock(&tfd->tfd_lock);
	if ((events & (POLLIN|POLLRDNORM)) && tfd->tfd_count > 0)
		revents |= events & (POLLIN|POLLRDNORM);
	if (revents == 0)
		selrecord(td, &tfd->tfd_sel);
	mtx_unlock(&tfd->tfd_lock);

	return (revents);
}

static int
timerfd_kqfilter(struct file *fp, struct knote *kn)
{
	struct timerfd *tfd;

	tfd = fp->f_data;
	if (fp->f_type != DTYPE_LINUXTFD || tfd == NULL)
		return (EINVAL);

	if (kn->kn_filter == EVFILT_READ)
		kn->kn_fop = &timerfd_rfiltops;
	else
		return (EINVAL);

	kn->kn_hook = tfd;
	knlist_add(&tfd->tfd_sel.si_note, kn, 0);

	return (0);
}

static void
filt_timerfddetach(struct knote *kn)
{
	struct timerfd *tfd = kn->kn_hook;

	mtx_lock(&tfd->tfd_lock);
	knlist_remove(&tfd->tfd_sel.si_note, kn, 1);
	mtx_unlock(&tfd->tfd_lock);
}

static int
filt_timerfdread(struct knote *kn, long hint)
{
	struct timerfd *tfd = kn->kn_hook;

	return (tfd->tfd_count > 0);
}

static int
timerfd_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{

	if (fp->f_data == NULL || fp->f_type != DTYPE_LINUXTFD)
		return (EINVAL);

	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		return (0);
	}

	return (ENOTTY);
}

static int
timerfd_stat(struct file *fp, struct stat *st, struct ucred *active_cred)
{

	return (ENXIO);
}

static int
timerfd_fill_kinfo(struct file *fp, struct kinfo_file *kif, struct filedesc *fdp)
{

	kif->kf_type = KF_TYPE_UNKNOWN;
	return (0);
}

static void
linux_timerfd_clocktime(struct timerfd *tfd, struct timespec *ts)
{

	if (tfd->tfd_clockid == CLOCK_REALTIME)
		getnanotime(ts);
	else	/* CLOCK_MONOTONIC */
		getnanouptime(ts);
}

static void
linux_timerfd_curval(struct timerfd *tfd, struct itimerspec *ots)
{
	struct timespec cts;

	linux_timerfd_clocktime(tfd, &cts);
	*ots = tfd->tfd_time;
	if (ots->it_value.tv_sec != 0 || ots->it_value.tv_nsec != 0) {
		timespecsub(&ots->it_value, &cts, &ots->it_value);
		if (ots->it_value.tv_sec < 0 ||
		    (ots->it_value.tv_sec == 0 &&
		     ots->it_value.tv_nsec == 0)) {
			ots->it_value.tv_sec  = 0;
			ots->it_value.tv_nsec = 1;
		}
	}
}

static int
linux_timerfd_gettime_common(struct thread *td, int fd, struct itimerspec *ots)
{
	struct timerfd *tfd;
	struct file *fp;
	int error;

	error = fget(td, fd, &cap_read_rights, &fp);
	if (error != 0)
		return (error);
	tfd = fp->f_data;
	if (fp->f_type != DTYPE_LINUXTFD || tfd == NULL) {
		error = EINVAL;
		goto out;
	}

	mtx_lock(&tfd->tfd_lock);
	linux_timerfd_curval(tfd, ots);
	mtx_unlock(&tfd->tfd_lock);

out:
	fdrop(fp, td);
	return (error);
}

int
linux_timerfd_gettime(struct thread *td, struct linux_timerfd_gettime_args *args)
{
	struct l_itimerspec lots;
	struct itimerspec ots;
	int error;

	error = linux_timerfd_gettime_common(td, args->fd, &ots);
	if (error != 0)
		return (error);
	error = native_to_linux_itimerspec(&lots, &ots);
	if (error == 0)
		error = copyout(&lots, args->old_value, sizeof(lots));
	return (error);
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_timerfd_gettime64(struct thread *td, struct linux_timerfd_gettime64_args *args)
{
	struct l_itimerspec64 lots;
	struct itimerspec ots;
	int error;

	error = linux_timerfd_gettime_common(td, args->fd, &ots);
	if (error != 0)
		return (error);
	error = native_to_linux_itimerspec64(&lots, &ots);
	if (error == 0)
		error = copyout(&lots, args->old_value, sizeof(lots));
	return (error);
}
#endif

static int
linux_timerfd_settime_common(struct thread *td, int fd, int flags,
    struct itimerspec *nts, struct itimerspec *oval)
{
	struct timespec cts, ts;
	struct timerfd *tfd;
	struct timeval tv;
	struct file *fp;
	int error;

	if ((flags & ~LINUX_TFD_SETTIME_FLAGS) != 0)
		return (EINVAL);

	error = fget(td, fd, &cap_write_rights, &fp);
	if (error != 0)
		return (error);
	tfd = fp->f_data;
	if (fp->f_type != DTYPE_LINUXTFD || tfd == NULL) {
		error = EINVAL;
		goto out;
	}

	mtx_lock(&tfd->tfd_lock);
	if (!timespecisset(&nts->it_value))
		timespecclear(&nts->it_interval);
	if (oval != NULL)
		linux_timerfd_curval(tfd, oval);

	bcopy(nts, &tfd->tfd_time, sizeof(*nts));
	tfd->tfd_count = 0;
	if (timespecisset(&nts->it_value)) {
		linux_timerfd_clocktime(tfd, &cts);
		ts = nts->it_value;
		if ((flags & LINUX_TFD_TIMER_ABSTIME) == 0) {
			timespecadd(&tfd->tfd_time.it_value, &cts,
				&tfd->tfd_time.it_value);
		} else {
			timespecsub(&ts, &cts, &ts);
		}
		TIMESPEC_TO_TIMEVAL(&tv, &ts);
		callout_reset(&tfd->tfd_callout, tvtohz(&tv),
			linux_timerfd_expire, tfd);
		tfd->tfd_canceled = false;
	} else {
		tfd->tfd_canceled = true;
		callout_stop(&tfd->tfd_callout);
	}
	mtx_unlock(&tfd->tfd_lock);

out:
	fdrop(fp, td);
	return (error);
}

int
linux_timerfd_settime(struct thread *td, struct linux_timerfd_settime_args *args)
{
	struct l_itimerspec lots;
	struct itimerspec nts, ots, *pots;
	int error;

	error = copyin(args->new_value, &lots, sizeof(lots));
	if (error != 0)
		return (error);
	error = linux_to_native_itimerspec(&nts, &lots);
	if (error != 0)
		return (error);
	pots = (args->old_value != NULL ? &ots : NULL);
	error = linux_timerfd_settime_common(td, args->fd, args->flags,
	    &nts, pots);
	if (error == 0 && args->old_value != NULL) {
		error = native_to_linux_itimerspec(&lots, &ots);
		if (error == 0)
			error = copyout(&lots, args->old_value, sizeof(lots));
	}
	return (error);
}

#if defined(__i386__) || (defined(__amd64__) && defined(COMPAT_LINUX32))
int
linux_timerfd_settime64(struct thread *td, struct linux_timerfd_settime64_args *args)
{
	struct l_itimerspec64 lots;
	struct itimerspec nts, ots, *pots;
	int error;

	error = copyin(args->new_value, &lots, sizeof(lots));
	if (error != 0)
		return (error);
	error = linux_to_native_itimerspec64(&nts, &lots);
	if (error != 0)
		return (error);
	pots = (args->old_value != NULL ? &ots : NULL);
	error = linux_timerfd_settime_common(td, args->fd, args->flags,
	    &nts, pots);
	if (error == 0 && args->old_value != NULL) {
		error = native_to_linux_itimerspec64(&lots, &ots);
		if (error == 0)
			error = copyout(&lots, args->old_value, sizeof(lots));
	}
	return (error);
}
#endif

static void
linux_timerfd_expire(void *arg)
{
	struct timespec cts, ts;
	struct timeval tv;
	struct timerfd *tfd;

	tfd = (struct timerfd *)arg;

	linux_timerfd_clocktime(tfd, &cts);
	if (timespeccmp(&cts, &tfd->tfd_time.it_value, >=)) {
		if (timespecisset(&tfd->tfd_time.it_interval))
			timespecadd(&tfd->tfd_time.it_value,
				    &tfd->tfd_time.it_interval,
				    &tfd->tfd_time.it_value);
		else
			/* single shot timer */
			timespecclear(&tfd->tfd_time.it_value);
		if (timespecisset(&tfd->tfd_time.it_value)) {
			timespecsub(&tfd->tfd_time.it_value, &cts, &ts);
			TIMESPEC_TO_TIMEVAL(&tv, &ts);
			callout_reset(&tfd->tfd_callout, tvtohz(&tv),
				linux_timerfd_expire, tfd);
		}
		tfd->tfd_count++;
		KNOTE_LOCKED(&tfd->tfd_sel.si_note, 0);
		selwakeup(&tfd->tfd_sel);
		wakeup(&tfd->tfd_count);
	} else if (timespecisset(&tfd->tfd_time.it_value)) {
		timespecsub(&tfd->tfd_time.it_value, &cts, &ts);
		TIMESPEC_TO_TIMEVAL(&tv, &ts);
		callout_reset(&tfd->tfd_callout, tvtohz(&tv),
		    linux_timerfd_expire, tfd);
	}
}
