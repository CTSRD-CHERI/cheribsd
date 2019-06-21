/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include <cheri/cheric.h>

/*
 * A series of self tests relating to the pure-capability kernel and bounds
 * set up for various mbuf-related allocators and components.  There are two
 * classes of tests: non-destructive, which perform various activities and
 * assert various properties (such as suitable bounds); and destructive tests,
 * which are intended to trigger kernel faults (e.g., due to violating
 * bounds).
 *
 * XXXRW: It might be nice to think about whether a custom fault handler for
 * the test thread might be used to make the destructive tests
 * non-destructive.
 */

SYSCTL_NODE(_security_cheri, OID_AUTO, test_mbuf, CTLFLAG_RD, 0,
    "Kernel CHERI self tests");

/*
 * Non-destructive tests for bounds on in-mbuf data.
 */
static int
sysctl_cheri_test_mbuf_mdat(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_get(M_WAITOK, MT_DATA);
	KASSERT(cheri_getbase(m->m_data) == (vaddr_t)&m->m_dat,
	    ("%s: cheri_getbase(m->m_data) != m->m_dat", __func__));
	KASSERT(cheri_getlen(m->m_data) == MLEN,
	    ("%s: cheri_getlen(m->m_data) != MLEN", __func__));
	mtod(m, char *)[0] = 0;
	mtod(m, char *)[MLEN-1] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mdat,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mdat, "I",
    "Non-destructive mbuf bounds test");

static int
sysctl_cheri_test_mbuf_mpktdat(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_gethdr(M_WAITOK, MT_DATA);
	KASSERT(cheri_getbase(m->m_data) == (vaddr_t)&m->m_pktdat,
	    ("%s: cheri_getbase(m->m_data) != m->m_pktdat", __func__));
	KASSERT(cheri_getlen(m->m_data) == MHLEN,
	    ("%s: cheri_getlen(m->m_data) != MHLEN", __func__));
	mtod(m, char *)[0] = 0;
	mtod(m, char *)[MHLEN-1] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mpktdat,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mpktdat, "I",
    "Non-destructive pkthdr mbuf bounds test");

/*
 * XXXRW: For now, just ordinary mbuf clusters, but need to add various
 * jumbogram-size things as well.
 */
static int
sysctl_cheri_test_mbuf_mcl(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_getcl(M_WAITOK, MT_DATA, 0);
	KASSERT(cheri_getbase(m->m_data) == (vaddr_t)&m->m_data,
	    ("(%s: cheri_getbase(m->m_data) != m->m_data", __func__));
	KASSERT(cheri_getlen(m->m_data) == MCLBYTES,
	    ("(%s: cheri_getlen(m->m_data) != MCLBYTES", __func__));
	mtod(m, char *)[0] = 0;
	mtod(m, char *)[MCLBYTES-1] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mcl,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mcl, "I",
    "Non-destructive mbuf cluster bounds test");

/*
 * Destructive tests for bounds on in-mbuf data.
 */
static int
sysctl_cheri_test_mbuf_mdat_lowerbound(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_get(M_WAITOK, MT_DATA);
	mtod(m, char *)[-1] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mdat_lowerbound,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mdat_lowerbound, "I",
    "Destructive mbuf lower-bound test");

static int
sysctl_cheri_test_mbuf_mdat_upperbound(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_getcl(M_WAITOK, MT_DATA, 0);

	m = m_get(M_WAITOK, MT_DATA);
	mtod(m, char *)[MLEN] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mdat_upperbound,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mdat_upperbound, "I",
    "Destructive mbuf upper-bound test");

static int
sysctl_cheri_test_mbuf_mpktdat_lowerbound(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_gethdr(M_WAITOK, MT_DATA);
	mtod(m, char *)[-1] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mpktdat_lowerbound,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mpktdat_lowerbound, "I",
    "Destructive pkthdr mbuf lower-bound test");

static int
sysctl_cheri_test_mbuf_mpktdat_upperbound(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_gethdr(M_WAITOK, MT_DATA);
	mtod(m, char *)[MHLEN] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mpktdat_upperbound,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mpktdat_upperbound, "I",
    "Destructive pkthdr mbuf upper-bound test");

/*
 * XXXRW: For now, just ordinary mbuf clusters, but need to add various
 * jumbogram-size things as well.
 */

static int
sysctl_cheri_test_mbuf_mcl_lowerbound(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_getcl(M_WAITOK, MT_DATA, 0);
	mtod(m, char *)[-1] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mcl_lowerbound,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mcl_lowerbound, "I",
    "Destructive mbuf cluster lower-bound test");

static int
sysctl_cheri_test_mbuf_mcl_upperbound(SYSCTL_HANDLER_ARGS)
{
	struct mbuf *m;
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val,0, req);
	if (error == 0|| req->newptr == NULL)
		return (error);
	if (val != 1)
		return (EINVAL);

	m = m_getcl(M_WAITOK, MT_DATA, 0);
	mtod(m, char *)[-1] = 0;
	m_free(m);
	return (0);
}
SYSCTL_PROC(_security_cheri_test_mbuf, 0, mcl_upperbound,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    sysctl_cheri_test_mbuf_mcl_upperbound, "I",
    "Destructive mbuf cluster upper-bound test");
