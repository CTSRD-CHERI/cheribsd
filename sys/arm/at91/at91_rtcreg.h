/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2006 M. Warner Losh.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $FreeBSD$ */

#ifndef ARM_AT91_AT91_RTCREG_H
#define ARM_AT91_AT91_RTCREG_H

/* Registers */
#define RTC_CR		0x00		/* RTC Control Register */
#define RTC_MR		0x04		/* RTC Mode Register */
#define RTC_TIMR	0x08		/* RTC Time Register */
#define RTC_CALR	0x0c		/* RTC Calendar Register */
#define RTC_TIMALR	0x10		/* RTC Time Alarm Register */
#define RTC_CALALR	0x14		/* RTC Calendar Alarm Register */
#define RTC_SR		0x18		/* RTC Status Register */
#define RTC_SCCR	0x1c		/* RTC Status Command Clear Register */
#define RTC_IER		0x20		/* RTC Interrupt Enable Register */
#define RTC_IDR		0x24		/* RTC Interrupt Disable Register */
#define RTC_IMR		0x28		/* RTC Interrupt Mask Register */
#define RTC_VER		0x2c		/* RTC Valid Entry Register */

/* CR */
#define	RTC_CR_UPDTIM	(0x1u <<  0)	/* Request update of time register */
#define	RTC_CR_UPDCAL	(0x1u <<  1)	/* Request update of calendar reg. */

/* TIMR */
#define RTC_TIMR_SEC_M	0x7fUL
#define RTC_TIMR_SEC_S	0
#define RTC_TIMR_SEC(x)	FROMBCD(((x) & RTC_TIMR_SEC_M) >> RTC_TIMR_SEC_S)
#define RTC_TIMR_MIN_M	0x7f00UL
#define RTC_TIMR_MIN_S	8
#define RTC_TIMR_MIN(x)	FROMBCD(((x) & RTC_TIMR_MIN_M) >> RTC_TIMR_MIN_S)
#define RTC_TIMR_HR_M	0x3f0000UL
#define RTC_TIMR_HR_S	16
#define RTC_TIMR_HR(x)	FROMBCD(((x) & RTC_TIMR_HR_M) >> RTC_TIMR_HR_S)
#define RTC_TIMR_MK(hr, min, sec) \
		((TOBCD(hr) << RTC_TIMR_HR_S) | \
		 (TOBCD(min) << RTC_TIMR_MIN_S) | \
		 (TOBCD(sec) << RTC_TIMR_SEC_S))
#define RTC_TIMR_PM	(1UL << 22)

/* CALR */
#define RTC_CALR_CEN_M	0x0000007fUL
#define RTC_CALR_CEN_S	0
#define RTC_CALR_CEN(x)	FROMBCD(((x) & RTC_CALR_CEN_M) >> RTC_CALR_CEN_S)
#define RTC_CALR_YEAR_M	0x0000ff00UL
#define RTC_CALR_YEAR_S 8
#define RTC_CALR_YEAR(x) FROMBCD(((x) & RTC_CALR_YEAR_M) >> RTC_CALR_YEAR_S)
#define RTC_CALR_MON_M	0x001f0000UL
#define RTC_CALR_MON_S	16
#define RTC_CALR_MON(x)	FROMBCD(((x) & RTC_CALR_MON_M) >> RTC_CALR_MON_S)
#define RTC_CALR_DOW_M	0x00d0000UL
#define RTC_CALR_DOW_S	21
#define RTC_CALR_DOW(x)	FROMBCD(((x) & RTC_CALR_DOW_M) >> RTC_CALR_DOW_S)
#define RTC_CALR_DAY_M	0x3f000000UL
#define RTC_CALR_DAY_S	24
#define RTC_CALR_DAY(x)	FROMBCD(((x) & RTC_CALR_DAY_M) >> RTC_CALR_DAY_S)
#define RTC_CALR_MK(yr, mon, day, dow) \
		((TOBCD((yr) / 100) << RTC_CALR_CEN_S) | \
		 (TOBCD((yr) % 100) << RTC_CALR_YEAR_S) | \
		 (TOBCD(mon) << RTC_CALR_MON_S) | \
		 (TOBCD(dow) << RTC_CALR_DOW_S) | \
		 (TOBCD(day) << RTC_CALR_DAY_S))

/* SR */

#define	RTC_SR_ACKUPD		(0x1u <<  0)	/* Acknowledge for Update */
#define	RTC_SR_ALARM		(0x1u <<  1)	/* Alarm Flag */
#define	RTC_SR_SECEV		(0x1u <<  2)	/* Second Event */
#define	RTC_SR_TIMEV		(0x1u <<  3)	/* Time Event */
#define	RTC_SR_CALEV		(0x1u <<  4)	/* Calendar event */

/* VER */

#define	RTC_VER_NVTIM		(0x1 << 0)	/* Non-valid time */
#define	RTC_VER_NVCAL		(0x1 << 1)	/* Non-valid calendar */
#define	RTC_VER_NVTIMALR	(0x1 << 2)	/* Non-valid time alarm */
#define	RTC_VER_NVCALALR	(0x1 << 3)	/* Non-valid calendar alarm */

#endif /* ARM_AT91_AT91_RTCREG_H */
