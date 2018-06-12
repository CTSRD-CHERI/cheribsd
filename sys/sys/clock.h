/*-
 * Copyright (c) 1996 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Gordon W. Ross
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *	$NetBSD: clock_subr.h,v 1.7 2000/10/03 13:41:07 tsutsui Exp $
 *
 *
 * This file is the central clearing-house for calendrical issues.
 *
 * In general the kernel does not know about minutes, hours, days, timezones,
 * daylight savings time, leap-years and such.  All that is theoretically a
 * matter for userland only.
 *
 * Parts of kernel code does however care: badly designed filesystems store
 * timestamps in local time and RTC chips sometimes track time in a local
 * timezone instead of UTC and so on.
 *
 * All that code should go here for service.
 *
 * $FreeBSD$
 */

#ifndef _SYS_CLOCK_H_
#define _SYS_CLOCK_H_

#ifdef _KERNEL		/* No user serviceable parts */

/*
 * Timezone info from settimeofday(2), usually not used
 */
extern int tz_minuteswest;
extern int tz_dsttime;

int utc_offset(void);

/*
 * Structure to hold the values typically reported by time-of-day clocks.
 * This can be passed to the generic conversion functions to be converted
 * to a struct timespec.
 */
struct clocktime {
	int	year;			/* year (4 digit year) */
	int	mon;			/* month (1 - 12) */
	int	day;			/* day (1 - 31) */
	int	hour;			/* hour (0 - 23) */
	int	min;			/* minute (0 - 59) */
	int	sec;			/* second (0 - 59) */
	int	dow;			/* day of week (0 - 6; 0 = Sunday) */
	long	nsec;			/* nano seconds */
};

int clock_ct_to_ts(struct clocktime *, struct timespec *);
void clock_ts_to_ct(struct timespec *, struct clocktime *);

/*
 * Time-of-day clock functions and flags.  These functions might sleep.
 *
 * clock_register and clock_unregister() do what they say.  Upon return from
 * unregister, the clock's methods are not running and will not be called again.
 *
 * clock_schedule() requests that a registered clock's clock_settime() calls
 * happen at the given offset into the second.  The default is 0, meaning no
 * specific scheduling.  To schedule the call as soon after top-of-second as
 * possible, specify 1.  Each clock has its own schedule, but taskqueue_thread
 * is shared by many tasks; the timing of the call is not guaranteed.
 *
 * Flags:
 *
 *  CLOCKF_SETTIME_NO_TS
 *    Do not pass a timespec to clock_settime(), the driver obtains its own time
 *    and applies its own adjustments (this flag implies CLOCKF_SETTIME_NO_ADJ).
 *
 *  CLOCKF_SETTIME_NO_ADJ
 *    Do not apply utc offset and resolution/accuracy adjustments to the value
 *    passed to clock_settime(), the driver applies them itself.
 *
 *  CLOCKF_GETTIME_NO_ADJ
 *    Do not apply utc offset and resolution/accuracy adjustments to the value
 *    returned from clock_gettime(), the driver has already applied them.
 */

#define	CLOCKF_SETTIME_NO_TS	0x00000001
#define	CLOCKF_SETTIME_NO_ADJ	0x00000002
#define	CLOCKF_GETTIME_NO_ADJ	0x00000004

void clock_register(device_t _clockdev, long _resolution_us);
void clock_register_flags(device_t _clockdev, long _resolution_us, int _flags);
void clock_schedule(device_t clockdev, u_int _offsetns);
void clock_unregister(device_t _clockdev);

/*
 * BCD to decimal and decimal to BCD.
 */
#define	FROMBCD(x)	bcd2bin(x)
#define	TOBCD(x)	bin2bcd(x)

/* Some handy constants. */
#define SECDAY		(24 * 60 * 60)
#define SECYR		(SECDAY * 365)

/* Traditional POSIX base year */
#define	POSIX_BASE_YEAR	1970

void timespec2fattime(struct timespec *tsp, int utc, u_int16_t *ddp, u_int16_t *dtp, u_int8_t *dhp);
void fattime2timespec(unsigned dd, unsigned dt, unsigned dh, int utc, struct timespec *tsp);

#endif /* _KERNEL */

#endif /* !_SYS_CLOCK_H_ */
