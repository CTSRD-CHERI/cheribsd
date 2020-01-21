/*-
 * Copyright (c) 2018 SRI International
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ffclock.h"

#define	EXPLICIT_USER_ACCESS

#include <sys/param.h>
#include <sys/timeffc.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/timex.h>

#include <compat/cheriabi/cheriabi_proto.h>

/*
 * kern_ffclock.c
 */
int
cheriabi_ffclock_getcounter(struct thread *td,
    struct cheriabi_ffclock_getcounter_args *uap)
{
#ifdef	FFCLOCK
	ffcounter ffcount;

	ffcount = 0;
	ffclock_read_counter(&ffcount);
	if (ffcount == 0)
		return (EAGAIN);
	return (copyout(&ffcount, uap->ffcount, sizeof(ffcounter)));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_ffclock_setestimate(struct thread *td,
    struct cheriabi_ffclock_setestimate_args *uap)
{

#ifdef	FFCLOCK
	return (kern_ffclock_setestimate(td, uap->cest));
#else
	return (ENOSYS);
#endif
}

int
cheriabi_ffclock_getestimate(struct thread *td,
    struct cheriabi_ffclock_getestimate_args *uap)
{

#ifdef	FFCLOCK
	return (kern_ffclock_getestimate(td, uap->cest));
#else
	return (ENOSYS);
#endif
}

/*
 * kern_ntptime.c
 */
int
cheriabi_ntp_gettime(struct thread *td, struct cheriabi_ntp_gettime_args *uap)
{

	return (kern_ntp_gettime(td, uap->ntvp));
}

int
cheriabi_ntp_adjtime(struct thread *td, struct cheriabi_ntp_adjtime_args *uap)
{
	struct timex ntv;
	int error, retval;

	error = copyin(uap->tp, &ntv, sizeof(ntv));
	if (error != 0)
		return (error);
	error = kern_ntp_adjtime(td, &ntv, &retval);
	if (error != 0)
		return (error);
	error = copyout(&ntv, uap->tp, sizeof(ntv));
	if (error == 0)
		td->td_retval[0] = retval;
	return (error);
}

int
cheriabi_adjtime(struct thread *td, struct cheriabi_adjtime_args *uap)
{
	struct timeval delta, olddelta, *deltap;
	int error;

	if (uap->delta) {
		error = copyin(uap->delta, &delta, sizeof(delta));
		if (error != 0)
			return (error);
		deltap = &delta;
	} else
		deltap = NULL;
	error = kern_adjtime(td, deltap, &olddelta);
	if (uap->olddelta && error == 0)
		error = copyout(&olddelta, uap->olddelta, sizeof(olddelta));
	return (error);
}

/*
 * kern_time.c
 */

int
cheriabi_clock_getcpuclockid2(struct thread *td,
    struct cheriabi_clock_getcpuclockid2_args *uap)
{
	clockid_t clk_id;
	int error;

	error = kern_clock_getcpuclockid2(td, uap->id, uap->which, &clk_id);
	if (error == 0)
		error = copyout(&clk_id, uap->clock_id, sizeof(clockid_t));

	return (error);
}

int
cheriabi_clock_gettime(struct thread *td,
    struct cheriabi_clock_gettime_args *uap)
{
	struct timespec ats;
	int error;

	error = kern_clock_gettime(td, uap->clock_id, &ats);
	if (error == 0)
		error = copyout(&ats, uap->tp, sizeof(ats));

	return (error);
}

int
cheriabi_clock_settime(struct thread *td,
    struct cheriabi_clock_settime_args *uap)
{
	struct timespec ats;
	int error;

	error = copyin(uap->tp, &ats, sizeof(ats));
	if (error != 0)
		return (error);

	return (kern_clock_settime(td, uap->clock_id, &ats));
}

int
cheriabi_clock_getres(struct thread *td,
    struct cheriabi_clock_getres_args *uap)
{
	struct timespec ats;
	int error;

	if (uap->tp == NULL)
		return (0);

	error = kern_clock_getres(td, uap->clock_id, &ats);
	if (error == 0)
		error = copyout(&ats, uap->tp, sizeof(ats));
	
	return (error);
}

int
cheriabi_nanosleep(struct thread *td, struct cheriabi_nanosleep_args *uap)
{

	return (user_clock_nanosleep(td, CLOCK_REALTIME, TIMER_RELTIME,
	    uap->rqtp, uap->rmtp));
}

int
cheriabi_clock_nanosleep(struct thread *td,
    struct cheriabi_clock_nanosleep_args *uap)
{
	int error;

	error = user_clock_nanosleep(td, uap->clock_id, uap->flags, uap->rqtp,
	    uap->rmtp);
	return (kern_posix_error(td, error));
}

int
cheriabi_gettimeofday(struct thread *td, struct cheriabi_gettimeofday_args *uap)
{

	return (kern_gettimeofday(td, uap->tp, uap->tzp));
}

int
cheriabi_settimeofday(struct thread *td,
    struct cheriabi_settimeofday_args *uap)
{

	return (user_settimeofday(td, uap->tv, uap->tzp));
}

int
cheriabi_getitimer(struct thread *td, struct cheriabi_getitimer_args *uap)
{
	struct itimerval aitv;
	int error;

	error = kern_getitimer(td, uap->which, &aitv);
	if (error != 0)
		return (error);
	return (copyout(&aitv, uap->itv, sizeof (struct itimerval)));
}

int
cheriabi_setitimer(struct thread *td, struct cheriabi_setitimer_args *uap)
{
	struct itimerval aitv, oitv;
	int error;

	if (uap->itv == NULL) {
		error = kern_getitimer(td, uap->which, &aitv);
		if (error != 0)
			return (error);
		return (copyout(&aitv, uap->oitv, sizeof (struct itimerval)));
	}

	error = copyin(uap->itv, &aitv, sizeof(struct itimerval));
	if (error != 0)
		return (error);
	error = kern_setitimer(td, uap->which, &aitv, &oitv);
	if (error != 0 || uap->oitv == NULL)
		return (error);
	return (copyout(&oitv, uap->oitv, sizeof(struct itimerval)));
}

int
cheriabi_ktimer_create(struct thread *td,
    struct cheriabi_ktimer_create_args *uap)
{
	struct sigevent ev, *evp;
	int error, id;

	if (uap->evp == NULL) {
		evp = NULL;
	} else {
		error = copyincap(uap->evp, &ev, sizeof(ev));
		if (error != 0)
			return (error);
		evp = &ev;
	}
	error = kern_ktimer_create(td, uap->clock_id, evp, &id, -1);
	if (error != 0)
		return (error);
	error = copyout(&id, uap->timerid, sizeof(int));
	if (error != 0)
		kern_ktimer_delete(td, id);
	return (error);
}

int
cheriabi_ktimer_settime(struct thread *td,
    struct cheriabi_ktimer_settime_args *uap)
{
	struct itimerspec val, oval, *ovalp;
	int error;

	error = copyin(uap->value, &val, sizeof(val));
	if (error != 0)
		return (error);
	ovalp = uap->ovalue != NULL ? &oval : NULL;
	error = kern_ktimer_settime(td, uap->timerid, uap->flags, &val, ovalp);
	if (error == 0 && uap->ovalue != NULL)
		error = copyout(ovalp, uap->ovalue, sizeof(*ovalp));
	return (error);
}

int
cheriabi_ktimer_gettime(struct thread *td,
    struct cheriabi_ktimer_gettime_args *uap)
{
	struct itimerspec val;
	int error;

	error = kern_ktimer_gettime(td, uap->timerid, &val);
	if (error == 0)
		error = copyout(&val, uap->value, sizeof(val));
	return (error);
}
