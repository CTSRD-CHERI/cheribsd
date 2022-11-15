/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2007 Robert N. M. Watson
 * Copyright (c) 2015 Allan Jude <allanjude@freebsd.org>
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
#include <sys/sysctl.h>
#include <sys/user.h>

#include <err.h>
#include <errno.h>
#include <libprocstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libutil.h>

#include "procstat.h"

void
procstat_vm(struct procstat *procstat, struct kinfo_proc *kipp)
{
	struct kinfo_vmentry *freep, *kve;
	int ptrwidth;
	int i, cnt;
	const char *str, *lstr;

#ifdef __CHERI_PURE_CAPABILITY__
	ptrwidth = 2*sizeof(kvaddr_t) + 2;
#else
	ptrwidth = 2*sizeof(void *) + 2;
#endif
	if ((procstat_opts & PS_OPT_NOHEADER) == 0) {
		if ((procstat_opts & PS_OPT_VERBOSE) == 0)
			xo_emit("{T:/%5s %*s %*s %-5s %4s %4s %3s %3s %-5s %-2s %-s}\n",
			    "PID", ptrwidth, "START", ptrwidth, "END", "PRT",
			    "RES", "PRES", "REF", "SHD", "FLAG", "TP", "PATH");
		else
			xo_emit("{T:/%5s %*s %*s %*s %-5s %4s %4s %3s %3s %-5s %-2s %-s}\n",
			    "PID", ptrwidth, "START", ptrwidth, "END",
			    ptrwidth, "RESERV", "PRT",
			    "RES", "PRES", "REF", "SHD", "FLAG", "TP", "PATH");
	}

	xo_emit("{ek:process_id/%d}", kipp->ki_pid);

	freep = procstat_getvmmap(procstat, kipp, &cnt);
	if (freep == NULL)
		return;
	xo_open_list("vm");
	for (i = 0; i < cnt; i++) {
		xo_open_instance("vm");
		kve = &freep[i];
		if (kve->kve_pid == 0)
			xo_emit("{dk:process_id/%5s} ", "-");
		else
			xo_emit("{dk:process_id/%5d} ", kve->kve_pid);
		xo_emit("{d:kve_start/%#*jx} ", ptrwidth,
		    (uintmax_t)kve->kve_start);
		xo_emit("{d:kve_end/%#*jx} ", ptrwidth,
		    (uintmax_t)kve->kve_end);
		if ((procstat_opts & PS_OPT_VERBOSE) != 0)
			xo_emit("{d:kve_reservation/%#*jx} ", ptrwidth,
			    (uintmax_t)kve->kve_reservation);
		xo_emit("{e:kve_start/%#jx}", (uintmax_t)kve->kve_start);
		xo_emit("{e:kve_end/%#jx}", (uintmax_t)kve->kve_end);
		xo_emit("{e:kve_reservation/%#jx}",
		    (uintmax_t)kve->kve_reservation);
		xo_emit("{d:read/%s}", kve->kve_protection & KVME_PROT_READ ?
		    "r" : "-");
		xo_emit("{d:write/%s}", kve->kve_protection & KVME_PROT_WRITE ?
		    "w" : "-");
		xo_emit("{d:exec/%s}", kve->kve_protection & KVME_PROT_EXEC ?
		    "x" : "-");
		xo_emit("{d:read_cap/%s}", kve->kve_protection &
		    KVME_PROT_READ_CAP ? "R" : "-");
		xo_emit("{d:write_cap/%s} ", kve->kve_protection &
		    KVME_PROT_WRITE_CAP ? "W" : "-");
		xo_open_container("kve_protection");
		xo_emit("{en:read/%s}", kve->kve_protection & KVME_PROT_READ ?
		    "true" : "false");
		xo_emit("{en:write/%s}", kve->kve_protection & KVME_PROT_WRITE ?
		    "true" : "false");
		xo_emit("{en:exec/%s}", kve->kve_protection & KVME_PROT_EXEC ?
		    "true" : "false");
		xo_emit("{en:read_cap/%s}", kve->kve_protection &
		    KVME_PROT_READ_CAP ? "true" : "false");
		xo_emit("{en:write_cap/%s}", kve->kve_protection &
		    KVME_PROT_WRITE_CAP ? "true" : "false");
		xo_close_container("kve_protection");
		xo_emit("{:kve_resident/%4d/%d} ", kve->kve_resident);
		xo_emit("{:kve_private_resident/%4d/%d} ",
		    kve->kve_private_resident);
		xo_emit("{:kve_ref_count/%3d/%d} ", kve->kve_ref_count);
		xo_emit("{:kve_shadow_count/%3d/%d} ", kve->kve_shadow_count);
		/*
		 * Reuse the copy-on-write location for guard and
		 * unmapped pages.  This is a bit gross.
		 */
		if (kve->kve_flags & KVME_FLAG_COW)
			xo_emit("{d:copy_on_write/%-1s}", "C");
		else if (kve->kve_flags & KVME_FLAG_GUARD)
			xo_emit("{d:is_guard/%-1s}", "G");
		else if (kve->kve_flags & KVME_FLAG_UNMAPPED)
			xo_emit("{d:is_unmapped/%-1s}", "-");
		else
			xo_emit("{d:copy_on_write/%-1s}", "-");
		xo_emit("{d:need_copy/%-1s}", kve->kve_flags &
		    KVME_FLAG_NEEDS_COPY ? "N" : "-");
		xo_emit("{d:super_pages/%-1s}", kve->kve_flags &
		    KVME_FLAG_SUPER ? "S" : "-");
		xo_emit("{d:grows_down/%-1s}", kve->kve_flags &
		    KVME_FLAG_GROWS_UP ? "U" : kve->kve_flags &
		    KVME_FLAG_GROWS_DOWN ? "D" : "-");
		xo_emit("{d:wired/%-1s} ", kve->kve_flags &
		    KVME_FLAG_USER_WIRED ? "W" : "-");
		xo_open_container("kve_flags");
		xo_emit("{en:copy_on_write/%s}", kve->kve_flags &
		    KVME_FLAG_COW ? "true" : "false");
		xo_emit("{en:is_guard/%s}", kve->kve_flags &
		    KVME_FLAG_GUARD ? "true" : "false");
		xo_emit("{en:is_unmapped/%s}", kve->kve_flags &
		    KVME_FLAG_UNMAPPED ? "true" : "false");
		xo_emit("{en:needs_copy/%s}", kve->kve_flags &
		    KVME_FLAG_NEEDS_COPY ? "true" : "false");
		xo_emit("{en:super_pages/%s}", kve->kve_flags &
		    KVME_FLAG_SUPER ? "true" : "false");
		xo_emit("{en:grows_up/%s}", kve->kve_flags &
		    KVME_FLAG_GROWS_UP ? "true" : "false");
		xo_emit("{en:grows_down/%s}", kve->kve_flags &
		    KVME_FLAG_GROWS_DOWN ? "true" : "false");
		xo_emit("{en:wired/%s}", kve->kve_flags &
		    KVME_FLAG_USER_WIRED ? "true" : "false");
		xo_close_container("kve_flags");
		switch (kve->kve_type) {
		case KVME_TYPE_NONE:
			str = "--";
			lstr = "none";
			break;
		case KVME_TYPE_DEFAULT:
			str = "df";
			lstr = "default";
			break;
		case KVME_TYPE_VNODE:
			str = "vn";
			lstr = "vnode";
			break;
		case KVME_TYPE_SWAP:
			str = "sw";
			lstr = "swap";
			break;
		case KVME_TYPE_DEVICE:
			str = "dv";
			lstr = "device";
			break;
		case KVME_TYPE_PHYS:
			str = "ph";
			lstr = "physical";
			break;
		case KVME_TYPE_DEAD:
			str = "dd";
			lstr = "dead";
			break;
		case KVME_TYPE_SG:
			str = "sg";
			lstr = "scatter/gather";
			break;
		case KVME_TYPE_MGTDEVICE:
			str = "md";
			lstr = "managed_device";
			break;
		case KVME_TYPE_GUARD:
			str = "gd";
			lstr = "guard";
			break;
		case KVME_TYPE_UNKNOWN:
		default:
			str = "??";
			lstr = "unknown";
			break;
		}
		xo_emit("{d:kve_type/%-2s} ", str);
		xo_emit("{e:kve_type/%s}", lstr);
		xo_emit("{:kve_path/%-s/%s}\n", kve->kve_path);
		xo_close_instance("vm");
	}
	xo_close_list("vm");
	free(freep);
}
