/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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

#ifndef _DEV_DRM_PANFROST_ISSUES_H_
#define _DEV_DRM_PANFROST_ISSUES_H_

enum panfrost_hw_issue {
	HW_ISSUE_6367,
	HW_ISSUE_6787,
	HW_ISSUE_8186,
	HW_ISSUE_8245,
	HW_ISSUE_8316,
	HW_ISSUE_8394,
	HW_ISSUE_8401,
	HW_ISSUE_8408,
	HW_ISSUE_8443,
	HW_ISSUE_8987,
	HW_ISSUE_9435,
	HW_ISSUE_9510,
	HW_ISSUE_9630,
	HW_ISSUE_10327,
	HW_ISSUE_10649,
	HW_ISSUE_10676,
	HW_ISSUE_10797,
	HW_ISSUE_10817,
	HW_ISSUE_10883,
	HW_ISSUE_10959,
	HW_ISSUE_10969,
	HW_ISSUE_11020,
	HW_ISSUE_11024,
	HW_ISSUE_11035,
	HW_ISSUE_11056,
	HW_ISSUE_T76X_3542,
	HW_ISSUE_T76X_3953,
	HW_ISSUE_TMIX_8463,
	GPUCORE_1619,
	HW_ISSUE_TMIX_8438,
	HW_ISSUE_TGOX_R1_1234,
	HW_ISSUE_END
};

#define hw_issues_all (\
	(1 << HW_ISSUE_9435))

#define hw_issues_t600 (\
	(1 << HW_ISSUE_6367) | \
	(1 << HW_ISSUE_6787) | \
	(1 << HW_ISSUE_8408) | \
	(1 << HW_ISSUE_9510) | \
	(1 << HW_ISSUE_10649) | \
	(1 << HW_ISSUE_10676) | \
	(1 << HW_ISSUE_10883) | \
	(1 << HW_ISSUE_11020) | \
	(1 << HW_ISSUE_11035) | \
	(1 << HW_ISSUE_11056) | \
	(1 << HW_ISSUE_TMIX_8438))

#define hw_issues_t600_r0p0_15dev0 (\
	(1 << HW_ISSUE_8186) | \
	(1 << HW_ISSUE_8245) | \
	(1 << HW_ISSUE_8316) | \
	(1 << HW_ISSUE_8394) | \
	(1 << HW_ISSUE_8401) | \
	(1 << HW_ISSUE_8443) | \
	(1 << HW_ISSUE_8987) | \
	(1 << HW_ISSUE_9630) | \
	(1 << HW_ISSUE_10969) | \
	(1 << GPUCORE_1619))

#define hw_issues_t620 (\
	(1 << HW_ISSUE_10649) | \
	(1 << HW_ISSUE_10883) | \
	(1 << HW_ISSUE_10959) | \
	(1 << HW_ISSUE_11056) | \
	(1 << HW_ISSUE_TMIX_8438))

#define hw_issues_t620_r0p1 (\
	(1 << HW_ISSUE_10327) | \
	(1 << HW_ISSUE_10676) | \
	(1 << HW_ISSUE_10817) | \
	(1 << HW_ISSUE_11020) | \
	(1 << HW_ISSUE_11024) | \
	(1 << HW_ISSUE_11035))

#define hw_issues_t620_r1p0 (\
	(1 << HW_ISSUE_11020) | \
	(1 << HW_ISSUE_11024))

#define hw_issues_t720 (\
	(1 << HW_ISSUE_10649) | \
	(1 << HW_ISSUE_10797) | \
	(1 << HW_ISSUE_10883) | \
	(1 << HW_ISSUE_11056) | \
	(1 << HW_ISSUE_TMIX_8438))

#define hw_issues_t760 (\
	(1 << HW_ISSUE_10883) | \
	(1 << HW_ISSUE_T76X_3953) | \
	(1 << HW_ISSUE_TMIX_8438))

#define hw_issues_t760_r0p0 (\
	(1 << HW_ISSUE_11020) | \
	(1 << HW_ISSUE_11024) | \
	(1 << HW_ISSUE_T76X_3542))

#define hw_issues_t760_r0p1 (\
	(1 << HW_ISSUE_11020) | \
	(1 << HW_ISSUE_11024) | \
	(1 << HW_ISSUE_T76X_3542))

#define hw_issues_t760_r0p1_50rel0 (\
	(1 << HW_ISSUE_T76X_3542))

#define hw_issues_t760_r0p2 (\
	(1 << HW_ISSUE_11020) | \
	(1 << HW_ISSUE_11024) | \
	(1 << HW_ISSUE_T76X_3542))

#define hw_issues_t760_r0p3 (\
	(1 << HW_ISSUE_T76X_3542))

#define hw_issues_t820 (\
	(1 << HW_ISSUE_10883) | \
	(1 << HW_ISSUE_T76X_3953) | \
	(1 << HW_ISSUE_TMIX_8438))

#define hw_issues_t830 (\
	(1 << HW_ISSUE_10883) | \
	(1 << HW_ISSUE_T76X_3953) | \
	(1 << HW_ISSUE_TMIX_8438))

#define hw_issues_t860 (\
	(1 << HW_ISSUE_10883) | \
	(1 << HW_ISSUE_T76X_3953) | \
	(1 << HW_ISSUE_TMIX_8438))

#define hw_issues_t880 (\
	(1 << HW_ISSUE_10883) | \
	(1 << HW_ISSUE_T76X_3953) | \
	(1 << HW_ISSUE_TMIX_8438))

#define hw_issues_g31 0
#define hw_issues_g31_r1p0		(1 << HW_ISSUE_TGOX_R1_1234)
#define hw_issues_g51 0
#define hw_issues_g52 0
#define hw_issues_g71			((1 << HW_ISSUE_TMIX_8463) |\
					 (1 << HW_ISSUE_TMIX_8438))
#define hw_issues_g71_r0p0_05dev0	(1 << HW_ISSUE_T76X_3953)
#define hw_issues_g72 0
#define hw_issues_g76 0

static inline bool panfrost_has_hw_issue(struct panfrost_softc *sc,
    enum panfrost_hw_issue issue)
{

	if (sc->features.hw_issues & (1 << issue))
		return (true);

	return (false);
}

#endif /* !_DEV_DRM_PANFROST_ISSUES_H_ */
