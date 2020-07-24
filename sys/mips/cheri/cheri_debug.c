/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
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
 */

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/atomic.h>
#include <machine/pcb.h>
#include <machine/sysarch.h>

#ifdef DDB

static inline void
db_print_cap(const char* msg, void * __capability cap)
{
	db_printf("%s" _CHERI_PRINTF_CAP_FMT "\n", msg,
	    _CHERI_PRINTF_CAP_ARG(cap));
}

static void * __capability
cheri_getculr(void)
{
	void * __capability cap;

	__asm__ __volatile__ (
	    "creadhwr\t%0, $chwr_userlocal"
		: "=C" (cap));
	return (cap);
}

static void * __capability
cheri_getcplr(void)
{
	void * __capability cap;

	__asm__ __volatile__ (
	    "creadhwr\t%0, $chwr_priv_userlocal"
		: "=C" (cap));
	return (cap);
}

/*
 * Show the special capability registers that aren't GPRs.
 */
DB_SHOW_COMMAND(cp2, ddb_dump_cp2)
{
	register_t cause;
	uint8_t exccode, regnum;

	cause = cheri_getcause();
	exccode = (cause & CHERI_CAPCAUSE_EXCCODE_MASK) >>
	    CHERI_CAPCAUSE_EXCCODE_SHIFT;
	regnum = cause & CHERI_CAPCAUSE_REGNUM_MASK;
	db_printf("CHERI cause: ExcCode: 0x%02x ", exccode);
	if (regnum < 32)
		db_printf("RegNum: $c%02d ", regnum);
	else if (regnum == 255)
		db_printf("RegNum: $pcc ");
	else
		db_printf("RegNum: invalid (%d) ", regnum);
	db_printf("(%s)\n", cheri_exccode_string(exccode));

	db_print_cap("$ddc: ",  cheri_getdefault());
	db_print_cap("$pcc: ",  cheri_getpcc());
	db_print_cap("$culr: ", cheri_getculr());
	db_print_cap("$cplr: ", cheri_getcplr());
	db_print_cap("$kcc: ",  cheri_getkcc());
	db_print_cap("$kdc: ",  cheri_getkdc());
	db_print_cap("$epcc: ",  cheri_getepcc());
	db_print_cap("$kr1c: ",  cheri_getkr1c());
	db_print_cap("$kr2c: ",  cheri_getkr2c());
}

static void
db_show_cheri_trapframe(struct trapframe *frame)
{
	register_t cause;
	uint8_t exccode, regnum;
	u_int i;

	db_printf("Trapframe at %p\n", frame);
	cause = frame->capcause;
	exccode = (cause & CHERI_CAPCAUSE_EXCCODE_MASK) >>
	    CHERI_CAPCAUSE_EXCCODE_SHIFT;
	regnum = cause & CHERI_CAPCAUSE_REGNUM_MASK;
	db_printf("CHERI cause: ExcCode: 0x%02x ", exccode);
	if (regnum < 32)
		db_printf("RegNum: $c%02d ", regnum);
	else if (regnum == 255)
		db_printf("RegNum: $pcc ");
	else
		db_printf("RegNum: invalid (%d) ", regnum);
	db_printf("(%s)\n", cheri_exccode_string(exccode));

	db_print_cap("$ddc: ", frame->ddc);
	db_print_cap("$pcc: ", frame->pcc);
	/* Laboriously load and print each trapframe capability. */
	for (i = 1; i < 31; i++) {
		void * __capability cap = *(&frame->ddc + i);
		db_printf("$c%02d: " _CHERI_PRINTF_CAP_FMT "\n", i,
		    _CHERI_PRINTF_CAP_ARG(cap));
	}
}

/*
 * Variation that prints register state from the trap frame provided by KDB.
 */
DB_SHOW_COMMAND(cheri, ddb_dump_cheri)
{
	struct trapframe *frame;

	if (have_addr)
		frame = (struct trapframe *)addr;
	else
		frame = kdb_frame;
	db_show_cheri_trapframe(frame);
}

/*
 * Variation that prints the saved userspace CHERI register frame for a
 * thread.
 */
DB_SHOW_COMMAND(cheripcb, ddb_dump_cheripcb)
{
	struct thread *td;
	struct trapframe *frame;

	if (have_addr)
		td = db_lookup_thread(addr, TRUE);
	else
		td = curthread;

	frame = &td->td_pcb->pcb_regs;
	db_printf("Thread %d at %p\n", td->td_tid, td);
	db_show_cheri_trapframe(frame);
}
#endif
