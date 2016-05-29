/*-
 * Copyright (c) 2014-2015 SRI International
 * Copyright (c) 2012-2016 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Support for splitting captures into multiple files with a maximum
 * file size:
 *
 * Copyright (c) 2001
 *      Seth Webster <swebster@sst.ll.mit.edu>
 */

#include "config.h"

#include <sys/types.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/cheri_system.h>
#include <cheri/cheri_invoke.h>

#include <stdlib.h>
#include <string.h>
#include <md5.h>

#include "tcpdump-stdinc.h"
#include "netdissect.h"
#include "interface.h"
#include "print.h"

#include "tcpdump-helper.h"

static struct print_info printinfo;
static netdissect_options Gndo;
netdissect_options *gndo = &Gndo;
struct cheri_object g_next_object;
struct cheri_object cheri_tcpdump;

const char *program_name;

void	pawned(void);

int	invoke(void)
	    __attribute__((cheri_ccall)); /* XXXRW: Will be ccheri_ccallee. */
int
invoke(void)
{

	return (-1);
}

int
cheri_tcpdump_sandbox_init(bpf_u_int32 localnet, bpf_u_int32 netmask,
    uint32_t timezone_offset, const netdissect_options *ndo,
    struct cheri_object next_sandbox)
{

	program_name = "tcpdump-helper"; /* XXX: copy from parent? */

	/*
	 * Make a copy of the parent's netdissect_options.  Most of the
	 * items are unchanged until the next init or per-packet.
	 */
	memcpy_c(gndo, ndo, sizeof(netdissect_options));
	gndo->ndo_printf = tcpdump_printf;
	gndo->ndo_default_print = ndo_default_print;
	gndo->ndo_error = ndo_error;
	gndo->ndo_warning = ndo_warning;

	init_print(localnet, netmask, timezone_offset);

	printinfo.ndo_type = 1;
	printinfo.ndo = gndo;
	printinfo.p.ndo_printer = lookup_ndo_printer(gndo->ndo_dlt);
	if (printinfo.p.ndo_printer == NULL) {
		printinfo.p.printer = lookup_printer(gndo->ndo_dlt);
		printinfo.ndo_type = 0;
		if (printinfo.p.printer == NULL) {
			gndo->ndo_dltname =
			    pcap_datalink_val_to_name(gndo->ndo_dlt);
			if (gndo->ndo_dltname != NULL)
				error("packet printing is not supported for link type %s: use -w",
				      gndo->ndo_dltname);
		else
			error("packet printing is not supported for link type %d: use -w", gndo->ndo_dlt);
		}
	}

	g_next_object = next_sandbox;

	return (0);
}

int
cheri_sandbox_has_printer(int type)
{

	return (has_printer(type));
}

int
cheri_sandbox_pretty_print_packet(const struct pcap_pkthdr *h,
    const u_char *sp)
{
	int ret;

	ret = 0;

#ifdef DEBUG
	printf("printing a packet of length 0x%x\n", h->caplen);
	printf("sp b:%016jx l:%016zx o:%jx\n",
	    cheri_getbase((void *)sp),
	    cheri_getlen((void *)sp),
	    cheri_getoffset((void *)sp));
#endif

	gndo->ndo_packetp = sp;
	gndo->ndo_snapend = gndo->ndo_packetp + h->caplen;

	if (printinfo.ndo_type)
		ret = (*printinfo.p.ndo_printer)(printinfo.ndo,
		     h, gndo->ndo_packetp);
	else
		ret = (*printinfo.p.printer)(h, gndo->ndo_packetp);

	/* XXX: what else to reset? */
	gndo->ndo_packetp = NULL;
	snapend = NULL;

	return (ret);
}

void
pawned(void)
{

	printf(">>> ATTACKER OUTPUT <<<");
}
