/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2019 Jan Sucan <jansucan@FreeBSD.org>
 * All rights reserved.
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

#include <atf-c.h>

#include "../utils.h"

/*
 * Test cases.
 */

ATF_TC_WITHOUT_HEAD(aligned_even_length_big_endian);
ATF_TC_BODY(aligned_even_length_big_endian, tc)
{
	u_char data[] __aligned(sizeof(u_short)) =
		{0x12, 0x34, 0x56, 0x78};
	u_short sum;

	sum = in_cksum(data, nitems(data));
	ATF_REQUIRE(sum == 0x5397);
}

ATF_TC_WITHOUT_HEAD(aligned_odd_length_big_endian);
ATF_TC_BODY(aligned_odd_length_big_endian, tc)
{
	u_char data[] __aligned(sizeof(u_short)) =
		{0x12, 0x34, 0x56, 0x78, 0x9a};
	u_short sum;

	sum = in_cksum(data, nitems(data));
	ATF_REQUIRE(sum == 0x52fd);
}

ATF_TC_WITHOUT_HEAD(aligned_even_length_little_endian);
ATF_TC_BODY(aligned_even_length_little_endian, tc)
{
	u_char data[] __aligned(sizeof(u_short)) =
		{0x34, 0x12, 0x78, 0x56};
	u_short sum;

	sum = in_cksum(data, nitems(data));
	ATF_REQUIRE_MSG(sum == 0x9753, "%d", sum);
}

ATF_TC_WITHOUT_HEAD(aligned_odd_length_little_endian);
ATF_TC_BODY(aligned_odd_length_little_endian, tc)
{
	u_char data[] __aligned(sizeof(u_short)) =
		{0x34, 0x12, 0x78, 0x56, 0x00, 0x9a};
	u_short sum;

	sum = in_cksum(data, nitems(data));
	ATF_REQUIRE(sum == 0xfd52);
}

ATF_TC_WITHOUT_HEAD(unaligned_even_length_big_endian);
ATF_TC_BODY(unaligned_even_length_big_endian, tc)
{
	u_char data[] __aligned(sizeof(u_short)) =
		{0x00, 0x12, 0x34, 0x56, 0x78};
	u_short sum;

	sum = in_cksum(data + 1, nitems(data) - 1);
	ATF_REQUIRE(sum == 0x5397);
}

ATF_TC_WITHOUT_HEAD(unaligned_odd_length_big_endian);
ATF_TC_BODY(unaligned_odd_length_big_endian, tc)
{
	u_char data[] __aligned(sizeof(u_short)) =
		{0x00, 0x12, 0x34, 0x56, 0x78, 0x9a};
	u_short sum;

	sum = in_cksum(data + 1, nitems(data) - 1);
	ATF_REQUIRE(sum == 0x52fd);
}

ATF_TC_WITHOUT_HEAD(unaligned_even_length_little_endian);
ATF_TC_BODY(unaligned_even_length_little_endian, tc)
{
	u_char data[] __aligned(sizeof(u_short)) =
		{0x00, 0x34, 0x12, 0x78, 0x56};
	u_short sum;

	sum = in_cksum(data + 1, nitems(data) - 1);
	ATF_REQUIRE_MSG(sum == 0x9753, "%d", sum);
}

ATF_TC_WITHOUT_HEAD(unaligned_odd_length_little_endian);
ATF_TC_BODY(unaligned_odd_length_little_endian, tc)
{
	u_char data[] __aligned(sizeof(u_short)) =
		{0x00, 0x34, 0x12, 0x78, 0x56, 0x00, 0x9a};
	u_short sum;

	sum = in_cksum(data + 1, nitems(data) - 1);
	ATF_REQUIRE(sum == 0xfd52);
}

/*
 * Main.
 */

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, aligned_even_length_big_endian);
	ATF_TP_ADD_TC(tp, aligned_odd_length_big_endian);
	ATF_TP_ADD_TC(tp, aligned_even_length_little_endian);
	ATF_TP_ADD_TC(tp, aligned_odd_length_little_endian);
	ATF_TP_ADD_TC(tp, unaligned_even_length_big_endian);
	ATF_TP_ADD_TC(tp, unaligned_odd_length_big_endian);
	ATF_TP_ADD_TC(tp, unaligned_even_length_little_endian);
	ATF_TP_ADD_TC(tp, unaligned_odd_length_little_endian);

	return (atf_no_error());
}
