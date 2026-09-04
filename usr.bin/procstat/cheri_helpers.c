/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 SRI International
 * Copyright (c) 2024 Capabilities Limited
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001123C0031 ("MTSS").
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/user.h>

#include <cheri/c18n.h>
#include <cheri/revoke.h>
#include <cheri/revoke_kern.h>

#include <err.h>
#include <libprocstat.h>
#include <string.h>

#include "procstat.h"

const char *
get_quarantining(struct procstat *procstat, struct kinfo_proc *kipp)
{
	int quarantining;

	if (procstat_getquarantining(procstat, kipp, &quarantining) == 0) {
		switch (quarantining) {
		case 0:
			return ("no");
		case 1:
			return ("yes");
		case -1:
			return ("!");
		default:
			warnx("%s: unknown quarantining status", __func__);
			return ("?");
		}
	} else {
		return ("-");
	}
}

const char *
get_revoker_epoch(struct procstat *procstat, struct kinfo_proc *kipp)
{
	uint64_t epoch;
	static char revoker_epoch_buf[2*16 + 2 + 1]; /* 0x + number + NUL */

	if (procstat_get_revoker_epoch(procstat, kipp, &epoch) == 0) {
		switch (epoch) {
		case (uint64_t)-1:
			return ("na");
		default:
			snprintf(revoker_epoch_buf, sizeof(revoker_epoch_buf),
			    "%ju", (uintmax_t)epoch);
			return (revoker_epoch_buf);
		}
	} else {
		return ("-");
	}

}

const char *
get_revoker_state(struct procstat *procstat, struct kinfo_proc *kipp)
{
	int state;

	if (procstat_get_revoker_state(procstat, kipp, &state) == 0) {
		switch (state) {
		case CHERI_REVOKE_ST_NONE:
			return ("none");
		case CHERI_REVOKE_ST_INITING:
			return ("initing");
		case CHERI_REVOKE_ST_INITED:
			return ("inited");
		case CHERI_REVOKE_ST_CLOSING:
			return ("closing");
		case -1:
			return ("!");
		default:
			warnx("%s: unknown quarantining status", __func__);
			return ("?");
		}
	} else {
		return ("-");
	}
}
