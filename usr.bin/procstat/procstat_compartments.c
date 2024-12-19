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
#include <sys/user.h>

#include <cheri/c18n.h>

#include <err.h>
#include <libprocstat.h>

#include "procstat.h"

#define	C18N_MAX_COMPARTS	1024	/* Horrible but functional, for now. */
void
procstat_compartments(struct procstat *procstat __unused,
    struct kinfo_proc *kipp)
{
	struct cheri_c18n_compart *cccp, *ccc_incp;
	u_int i, ncomparts;

	ncomparts = C18N_MAX_COMPARTS;
	cccp = malloc(ncomparts * sizeof(*cccp));
	if (cccp == NULL) {
		warn("malloc");
		return;
	}
	if ((procstat_opts & PS_OPT_NOHEADER) == 0)
		xo_emit("{T:/%5s %-19s %4s %-32s}\n", "PID", "COMM", "CID",
		    "CNAME");
	if (procstat_getcompartments(procstat, kipp, cccp, &ncomparts) != 0) {
		if (errno != EPERM)
			warn("procstat_getcomparts");
		goto out;
	}
	ccc_incp = cccp;
	for (i = 0; i < ncomparts; i++, ccc_incp++) {
		if (ccc_incp->ccc_id == CHERI_C18N_COMPART_LAST)
			break;
		xo_emit("{k:process_id/%5d/%d}", kipp->ki_pid);
		xo_emit(" {:command/%-19s/%s}", kipp->ki_comm);
		xo_emit(" {:cid/%4d/%d}", ccc_incp->ccc_id);
		xo_emit(" {:cname/%-32s/%s}", ccc_incp->ccc_name);
		xo_emit("\n");
	}
out:
	free(cccp);
}
