/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025-2026 Capabilities Limited
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

#include <cheri/cheri_mrs.h>

#include <err.h>
#include <libprocstat.h>

#include "procstat.h"

void
procstat_mrs(struct procstat *procstat, struct kinfo_proc *kipp)
{
	struct cheri_mrs_stats cms;
	const char *kernel_epoch;

	/* XXXRW: Implement variable-length strings for byte counts. */
	if ((procstat_opts & PS_OPT_NOHEADER) == 0) {
		if ((procstat_opts & PS_OPT_VERBOSE) == 0)
			xo_emit(
			    "{T:/%5s %-19s %5s %4s %4s %7s %9s %7s %9s}\n",
			    "PID", "COMM", "FLAGS", "%TQR", "%MQR",
			    "CHEAP", "BHEAP", "CQUAR", "BQUAR");
		else
			xo_emit(
			    "{T:/%5s %-19s %5s %4s %4s %7s %9s %7s %9s "
			    "%9s %9s %9s %6s %6s %10u.%09u}\n",
			    "PID", "COMM", "FLAGS", "%TQR", "%MQR",
			    "CHEAP", "BHEAP", "CQUAR", "BQUAR",
			    "ASIZE", "MAXASIZE", "MINRVK", "UEPOCH", "KEPOCH",
			    "START");
	}

	xo_emit("{:process_id/%5d/%d}", kipp->ki_pid);
	xo_emit(" {:command/%-19s/%s}", kipp->ki_comm);

	if (procstat_getmrs(procstat, kipp, &cms) != 0 ||
	    cms.cms_version != CHERI_MRS_STATS_VERSION) {
		xo_emit(" {:mrs_flags/%5s/%s}", "-----");
		xo_emit(" {:mrs_max_ratio/%4s/%s}", "-");
		xo_emit(" {:mrs_ratio/%4s/%s}", "-");
		xo_emit(" {:mrs_count_inheap/%7s/%s}", "-");
		xo_emit(" {:mrs_bytes_inheap/%9s/%s}", "-");
		xo_emit(" {:mrs_count_inquarantine/%7s/%s}", "-");
		xo_emit(" {:mrs_bytes_inquarantine/%9s/%s}", "-");
		if ((procstat_opts & PS_OPT_VERBOSE) != 0) {
			xo_emit(" {:mrs_allocated_size/%9s/%s}", "-");
			xo_emit(" {:mrs_max_allocated_size/%9s/%s}", "-");
			xo_emit(" {:mrs_revocation_minimum/%9s/%s}", "-");
			xo_emit(" {:mrs_epoch/%6s/%s}", "-");
			xo_emit(" {:kernel_epoch/%6s/%s}", "-");
			xo_emit(" {:mrs_ts_start/%20s}", "-");
		}
		xo_emit("\n");
		return;
	}
	xo_emit(" {:mrs_flags/%c%c%c%c%c/%c%c%c%c%c}",
	    (cms.cms_mrs_flags & CHERI_MRS_FLAGS_ASYNCREVOKE) ? 'a' : '-',
	    (cms.cms_mrs_flags & CHERI_MRS_FLAGS_BOUNDPTRS) ? 'b' : '-',
	    (cms.cms_mrs_flags & CHERI_MRS_FLAGS_EVERYFREE) ? 'e' : '-',
	    (cms.cms_mrs_flags & CHERI_MRS_FLAGS_ABORTONFAIL) ? 'f' : '-',
	    (cms.cms_mrs_flags & CHERI_MRS_FLAGS_QUARANTINING) ? 'q' : '-');
	xo_emit(" {:mrs_max_ratio/%4zu/%zu}",
	    (100 * cms.cms_mrs_quarantine_numerator) /
	    cms.cms_mrs_quarantine_denominator);
	xo_emit(" {:mrs_ratio/%4zu/%zu}",
	    (100 * cms.cms_mrs_bytes_inquarantine) /
	    (cms.cms_mrs_bytes_inquarantine +
	    cms.cms_mrs_bytes_inheap));
	xo_emit(" {:mrs_count_inheap/%7zu/%zu",
	    cms.cms_mrs_count_inheap);
	xo_emit(" {:mrs_bytes_inheap/%9zu/%zu}",
	    cms.cms_mrs_bytes_inheap);
	xo_emit(" {:mrs_count_inquarantine/%7zu/%zu}",
	    cms.cms_mrs_count_inquarantine);
	xo_emit(" {:mrs_bytes_inquarantine/%9zu/%zu}",
	    cms.cms_mrs_bytes_inquarantine);
	if ((procstat_opts & PS_OPT_VERBOSE) != 0) {
		xo_emit(" {:mrs_allocated_size/%9zu/%zu}",
		    cms.cms_mrs_allocated_size);
		xo_emit(" {:mrs_max_allocated_size/%9zu/%zu}",
		    cms.cms_mrs_max_allocated_size);
		xo_emit(" {:mrs_revocation_minimum/%9zu/%zu}",
		    cms.cms_mrs_revocation_minimum);
		xo_emit(" {:mrs_epoch/%6zu/%zu}",
		    cms.cms_mrs_epoch);
		kernel_epoch = get_revoker_epoch(procstat, kipp);
		xo_emit(" {:kernel_epoch/%6s/%s}",
		    kernel_epoch != NULL ? kernel_epoch : "-");
		xo_emit(" {:mrs_s_start/%10u.%09u/%10u.%09u}",
		    cms.cms_mrs_ts_start.tv_sec,
		    cms.cms_mrs_ts_start.tv_nsec);
	}
	xo_emit("\n");
}
