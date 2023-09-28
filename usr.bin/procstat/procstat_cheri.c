/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001122S0003 ("MTSS").
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

#include <cheri/revoke.h>
#include <cheri/revoke_kern.h>

#include <err.h>
#include <libprocstat.h>
#include <string.h>

#include "procstat.h"

static char get_abi_cheri(struct kinfo_proc *kipp);
static const char *get_quarantining(struct procstat *procstat,
    struct kinfo_proc *kipp);
static const char *get_revoker_epoch(struct procstat *procstat,
    struct kinfo_proc *kipp);
static const char *get_revoker_state(struct procstat *procstat,
    struct kinfo_proc *kipp);

void
procstat_cheri(struct procstat *procstat, struct kinfo_proc *kipp)
{
	char abi_cheri;

	if ((procstat_opts & PS_OPT_NOHEADER) == 0) {
		if ((procstat_opts & PS_OPT_VERBOSE) == 0)
			xo_emit("{T:/%5s %-19s %c %4s %7s}\n",
			    "PID", "COMM", 'C', "QUAR", "RSTATE");
		else
			xo_emit("{T:/%5s %-19s %c %4s %7s %34s}\n",
			    "PID", "COMM", 'C', "QUAR", "RSTATE", "EPOCH");
	}

	xo_emit("{k:process_id/%5d/%d}", kipp->ki_pid);
	xo_emit(" {:command/%-19s/%s}", kipp->ki_comm);
	abi_cheri = get_abi_cheri(kipp);
	xo_emit(" {:abi_cheri_support/%c/%c}", abi_cheri);
	/* Don't print CHERI-specific things for non-CheriABI ABIs */
	switch (abi_cheri) {
	case 'P':
		xo_emit(" {:quarantining/%4s}",
		    get_quarantining(procstat, kipp));
		xo_emit(" {:revoker_state/%7s}",
		    get_revoker_state(procstat, kipp));
		if ((procstat_opts & PS_OPT_VERBOSE) != 0)
			xo_emit(" {:revoker_epoch/%34s}",
			    get_revoker_epoch(procstat, kipp));
		break;
	}
	xo_emit("\n");
}

static struct {
	const char *emul;
	char abi;
} abis[] = {
	{ "FreeBSD ELF64C", 'P' },
	{ "FreeBSD ELF64CB", 'P' },
	{ "FreeBSD ELF64", 'H' },
	{ "FreeBSD ELF32", '!' },
	{ "Linux ELF64", '!' },
	{ "Linux ELF32", '!' },
};

static char
get_abi_cheri(struct kinfo_proc *kipp)
{
	for (size_t i = 0; i < nitems(abis); i++)
		if (strcmp(abis[i].emul, kipp->ki_emul) == 0)
			return (abis[i].abi);
	return ('?');
}

static const char *
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

static const char *
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
			    "%#jx", (uintmax_t)epoch);
			return (revoker_epoch_buf);
		}
	} else {
		return ("-");
	}

}

static const char *
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
