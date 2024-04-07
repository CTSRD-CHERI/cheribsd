/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Capabilities Limited
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

#include <cheri/revoke.h>
#include <cheri/revoke_kern.h>

#include <err.h>
#include <libprocstat.h>
#include <string.h>
#include <rtld_c18n_public.h>

#include "procstat.h"

void
procstat_c18n(struct procstat *procstat, struct kinfo_proc *kipp)
{
	struct rtld_c18n_stats *rcsp;
	size_t len;

	if ((procstat_opts & PS_OPT_NOHEADER) == 0) {
		xo_emit("{T:/%5s %-19s %5s %5s %6s %5s %7s}\n",
			    "PID", "COMM", "COMP", "STKS", "TRAMPS", "TRPGS", "TRMPTBL");
	}

	if (procstat_getc18n(procstat, kipp, (void **)&rcsp, &len) < 0)
		return;
	xo_emit("{k:process_id/%5d/%d}", kipp->ki_pid);
	xo_emit(" {:command/%-19s/%s}", kipp->ki_comm);
	if (rcsp == NULL || len < sizeof(*rcsp)) {
		xo_emit(" {:compartments/%5s/%s}", "-");
		xo_emit(" {:stacks/%5s/%s}", "-");
		xo_emit(" {:trampolines/%6s/%s}", "-");
		xo_emit(" {:tramppages/%5s/%s}", "-");
		xo_emit(" {:tramptable/%7s/%s}", "-");
	} else {
		xo_emit(" {:compartments/%5lu/%lu}", rcsp->rcs_compartments);
		xo_emit(" {:stacks/%5lu/%lu}", rcsp->rcs_compartments);
		xo_emit(" {:trampolines/%6lju/%lu}", rcsp->rcs_trampolines);
		xo_emit(" {:tramppages/%5d/%d}", rcsp->rcs_tramppages);
		xo_emit(" {:tramptable/%7d/%d}", rcsp->rcs_tramptable);
	}
	xo_emit("\n");

	procstat_freec18n(procstat, rcsp);
}
