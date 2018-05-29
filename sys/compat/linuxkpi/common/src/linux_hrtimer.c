/*-
 * Copyright (c) 2017 Mark Johnston <markj@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/time.h>

#include <machine/cpu.h>

#include <linux/hrtimer.h>

/* hrtimer flags */
#define	HRTIMER_ACTIVE		0x01

static void
hrtimer_call_handler(void *arg)
{
	struct hrtimer *hrtimer;
	enum hrtimer_restart ret;

	hrtimer = arg;
	ret = hrtimer->function(hrtimer);
	MPASS(ret == HRTIMER_NORESTART);
	hrtimer->flags &= ~HRTIMER_ACTIVE;
}

bool
linux_hrtimer_active(struct hrtimer *hrtimer)
{
	bool ret;

	mtx_lock(&hrtimer->mtx);
	ret = (hrtimer->flags & HRTIMER_ACTIVE) != 0;
	mtx_unlock(&hrtimer->mtx);
	return (ret);
}

int
linux_hrtimer_cancel(struct hrtimer *hrtimer)
{

	if (!hrtimer_active(hrtimer))
		return (0);
	(void)callout_drain(&hrtimer->callout);
	return (1);
}

void
linux_hrtimer_init(struct hrtimer *hrtimer)
{

	hrtimer->function = NULL;
	hrtimer->flags = 0;
	mtx_init(&hrtimer->mtx, "hrtimer", NULL, MTX_DEF | MTX_RECURSE);
	callout_init_mtx(&hrtimer->callout, &hrtimer->mtx, 0);
}

void
linux_hrtimer_set_expires(struct hrtimer *hrtimer __unused,
    ktime_t time __unused)
{
}

void
linux_hrtimer_start(struct hrtimer *hrtimer, ktime_t time)
{

	linux_hrtimer_start_range_ns(hrtimer, time, 0);
}

void
linux_hrtimer_start_range_ns(struct hrtimer *hrtimer, ktime_t time, int64_t nsec)
{

	mtx_lock(&hrtimer->mtx);
	callout_reset_sbt(&hrtimer->callout, time.tv64 * SBT_1NS,
	    nsec * SBT_1NS, hrtimer_call_handler, hrtimer, 0);
	hrtimer->flags |= HRTIMER_ACTIVE;
	mtx_unlock(&hrtimer->mtx);
}
