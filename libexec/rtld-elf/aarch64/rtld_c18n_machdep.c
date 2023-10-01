/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021-2023 Dapeng Gao
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
#include <sys/mman.h>

#include <stdlib.h>

#include "debug.h"
#include "rtld.h"
#include "rtld_c18n.h"
#include "rtld_libc.h"

/*
 * libthr support
 */
void _rtld_thread_start(struct pthread *);
void _rtld_sighandler(int, siginfo_t *, void *);
void *get_rstk(const void *, uint32_t, tramp_stk_table_t);

/* Default stack size in libthr */
#define	DEFAULT_SANDBOX_STACK_SIZE	(sizeof(void *) / 4 * 1024 * 1024)

extern void (*thr_thread_start)(struct pthread *);

void
_rtld_thread_start(struct pthread *curthread)
{
	tramp_stk_table_t tls;
	asm ("mrs	%0, ctpidr_el0" : "=C" (tls));
	asm ("msr	rctpidr_el0, %0" :: "C" (tls));

	tls = xcalloc(DEFAULT_STACK_TABLE_SIZE, sizeof(*tls));
	tls[0] = _rtld_get_rstk;
	asm ("msr	ctpidr_el0, %0" :: "C" (tls));

	thr_thread_start(curthread);

	/*
	 * The previous call should never return, but this call is inserted so
	 * that the compiler generates a branch-and-link instruction for the
	 * previous call rather than a mere branch instruction. The content of
	 * the link register is required for the trampoline to work.
	 */
	rtld_die();
}

void
_rtld_thr_exit(long *state)
{
	tramp_stk_table_t tls;
	asm ("mrs	%0, ctpidr_el0" : "=C" (tls));

	ptraddr_t top = cheri_gettop(tls);
	for (tramp_stk_table_t cur = &tls[1]; (ptraddr_t)cur < top; ++cur) {
		void *stk = cheri_setaddress(*cur, cheri_getbase(*cur));
		if (stk != NULL && munmap(stk, DEFAULT_SANDBOX_STACK_SIZE) != 0)
			rtld_fatal("munmap failed");
	}
	free(tls);

	thr_exit(state);
}

extern void (*thr_sighandler)(int, siginfo_t *, void *);

void
_rtld_sighandler(int sig, siginfo_t *info, void *_ucp)
{
	uintptr_t csp, rcsp;
	ucontext_t *ucp = _ucp;

	csp = ucp->uc_mcontext.mc_capregs.cap_sp;
	asm ("mrs	%0, rcsp_el0" : "=C" (rcsp));
	ucp->uc_mcontext.mc_capregs.cap_sp = rcsp;
	/*
	 * If the program is interrupted while in Restricted mode, the value
	 * saved at the bottom of rcsp might not be the actual top of the stack.
	 * Thus, if the signal handler transitions to the compartment of the
	 * interrupted code, it would corrupt the stack.
	 */
	if (cheri_gettag(rcsp))
		((uintptr_t *)cheri_setaddress(rcsp, cheri_gettop(rcsp)))[-1] = rcsp;

	thr_sighandler(sig, info, ucp);

	rcsp = ucp->uc_mcontext.mc_capregs.cap_sp;
	asm ("msr	rcsp_el0, %0" :: "C" (rcsp));
	ucp->uc_mcontext.mc_capregs.cap_sp = csp;
}

/*
 * Trampolines
 */
void *
get_rstk(const void *target __unused, uint32_t cid, tramp_stk_table_t table)
{
	void **stk;
	size_t len = cheri_getlen(table) / sizeof(*table);

	assert(len <= cid || table[cid] == NULL);
	if (len <= cid) {
		size_t new_len = cid * 2;
		table = realloc(table, sizeof(*table) * new_len);
		if (table == NULL)
			rtld_fatal("realloc failed");
		memset(&table[len], 0, sizeof(*table) * (new_len - len));

		asm ("msr	ctpidr_el0, %0" :: "C" (table));
	}
	assert(table[cid] == NULL);

	len = DEFAULT_SANDBOX_STACK_SIZE;
	stk = mmap(NULL,
	    len,
	    PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE | MAP_STACK,
	    -1, 0);
	if (stk == MAP_FAILED)
		rtld_fatal("mmap failed");
	stk = (void **)((char *)stk + len);
	stk = cheri_clearperm(stk, CHERI_PERM_EXECUTIVE | CHERI_PERM_SW_VMEM);

	if (ld_compartment_utrace == NULL) {
		stk[-1] = &stk[-1];
	} else {
		stk[-1] = &stk[-2];
		stk[-2] = (void *)(uintptr_t)cid;
	}

	table[cid] = stk;

	return (stk);
}

size_t
tramp_compile(tramp **entry, const struct tramp_data *data)
{
#define IMPORT(template) \
	extern const uint32_t tramp_##template[]; \
	extern const size_t size_tramp_##template

	IMPORT(header);
	IMPORT(header_hook);
	IMPORT(header_res);
	IMPORT(save_caller);
	IMPORT(switch_stack);
	IMPORT(clear_regs);
	IMPORT(invoke_res);
	IMPORT(invoke_exe);
	IMPORT(return_hook);
	IMPORT(return);

#undef	IMPORT

	uint32_t *buf = (void *)*entry;
	size_t size = 0;
	bool executive = cheri_getperm(data->target) & CHERI_PERM_EXECUTIVE;
	bool hook = ld_compartment_utrace != NULL ||
	    ld_compartment_overhead != NULL;

#define	COPY(template) \
	do { \
		buf = mempcpy(buf, tramp_##template, size_tramp_##template); \
		size += size_tramp_##template; \
	} while(0)

	if (hook) {
		COPY(header_hook);
		*(*entry)++ = data->defobj;
		*(*entry)++ = data->def;
		*(*entry)++ = tramp_hook;
	} else
		COPY(header);

	*(*entry)++ = data->target;

	if (!executive) {
		COPY(header_res);
		buf[-2] |= (uint32_t)data->defobj->compart_id << 5;
	}

	COPY(save_caller);
	if (data->sig.valid)
		buf[-2] |= (uint32_t)data->sig.ret_args << 5;

	if (executive)
		COPY(invoke_exe);
	else {
		COPY(switch_stack);
		if (data->sig.valid) {
			if (!data->sig.mem_args) {
				buf = mempcpy(buf, tramp_clear_regs,
					sizeof(*tramp_clear_regs));
				size += sizeof(*tramp_clear_regs);
			}
			if (data->sig.ret_args != INDIRECT) {
				buf = mempcpy(buf, tramp_clear_regs + 1,
					sizeof(*tramp_clear_regs));
				size += sizeof(*tramp_clear_regs);
			}
			int to_clear = 8 - data->sig.reg_args;
			buf = mempcpy(buf, tramp_clear_regs + 2,
				sizeof(*tramp_clear_regs) * to_clear);
			size += sizeof(*tramp_clear_regs) * to_clear;
		}
		COPY(invoke_res);
	}

	if (hook)
		COPY(return_hook);

	COPY(return);

#undef	COPY

	return (size);
}

/*
 * APIs
 */
void *
_rtld_safebox_code(void *target, struct tramp_sig sig)
{
	const Obj_Entry *obj;

	if (!tramp_sig_legal(sig)) {
		_rtld_error(
		    "_rtld_sandbox_code: Invalid signature %02hhX",
		    tramp_sig_to_int(sig));
		return (NULL);
	}

	if ((cheri_getperm(target) & CHERI_PERM_EXECUTIVE) != 0)
		return (target);

	obj = obj_from_addr(target);
	if (obj == NULL) {
		_rtld_error(
		    "_rtld_sandbox_code: "
		    "%#p does not belong to any object", target);
		return (NULL);
	}

	if (sig.valid) {
		asm ("chkssu	%0, %0, %1\n"
		    : "+C" (target)
		    : "C" (obj->text_rodata_cap)
		    : "cc");
		target = cheri_seal(target,
		    sealer_tramp + tramp_sig_to_otype(sig));
	}

	return (target);
}

void *
_rtld_sandbox_code(void *target, struct tramp_sig sig)
{
	const Obj_Entry *obj;
	void *target_unsealed;

	if (!tramp_sig_legal(sig)) {
		_rtld_error(
		    "_rtld_sandbox_code: Invalid signature %02hhX",
		    tramp_sig_to_int(sig));
		return (NULL);
	}

	if ((cheri_getperm(target) & CHERI_PERM_EXECUTIVE) != 0)
		return (target);

	obj = obj_from_addr(target);
	if (obj == NULL) {
		_rtld_error(
		    "_rtld_sandbox_code: "
		    "%#p does not belong to any object", target);
		return (NULL);
	}

	target_unsealed = cheri_unseal(target, sealer_tramp);
	if (cheri_gettag(target_unsealed)) {
		if (sig.valid && cheri_gettype(target) !=
		    (long)cheri_getbase(sealer_tramp) + tramp_sig_to_otype(sig))
			rtld_fatal("Signature mismatch");
		target = cheri_sealentry(target_unsealed);
	}

	target = tramp_intern(NULL, &(struct tramp_data) {
		.target = target,
		.defobj = obj,
		.sig = sig
	});

	return (target);
}
