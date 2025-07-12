/*-
 * Copyright (c) 2019 Leandro Lupori
 * Copyright (c) 2024 Jessica Clarke <jrtc27@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

static unsigned long elf_hwcap;

static void
ifunc_init(const Elf_Auxinfo *aux)
{
	/* Digest the auxiliary vector. */
	for (; aux->a_type != AT_NULL; aux++) {
		switch (aux->a_type) {
		case AT_HWCAP:
			elf_hwcap = (uint32_t)aux->a_un.a_val;
			break;
		}
	}
}

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cheric.h>

#include <cheri_init_globals.h>

static void
crt1_handle_rela(const Elf_Rela *r, void *data_cap, const void *code_cap)
{
}

static void
crt1_handle_tgot_capreloc(const struct capreloc *r, void *tgot, Elf_Addr init,
    void *tls)
{
	uintptr_t *where, val;

	where = (uintptr_t *)((uintptr_t)tgot +
	    (r->capability_location - init));

	val = (uintptr_t)tls;
	if ((r->permissions & function_reloc_flag) == function_reloc_flag)
		__builtin_trap();
	else if ((r->permissions & constant_reloc_flag) == constant_reloc_flag)
		val = cheri_andperm(val, constant_pointer_permissions_mask);
	else
		val = cheri_andperm(val, global_pointer_permissions_mask);

	val = cheri_setaddress(val, r->object + (ptraddr_t)tls);
	val = cheri_setbounds(val, r->size);
	val += r->offset;
	*where = val;
}
#else
static void
crt1_handle_rela(const Elf_Rela *r)
{
	typedef Elf_Addr (*ifunc_resolver_t)(
	    unsigned long, unsigned long, unsigned long, unsigned long,
	    unsigned long, unsigned long, unsigned long, unsigned long);
	Elf_Addr *ptr, *where, target;

	switch (ELF_R_TYPE(r->r_info)) {
	case R_RISCV_IRELATIVE:
		ptr = (Elf_Addr *)r->r_addend;
		where = (Elf_Addr *)r->r_offset;
		target = ((ifunc_resolver_t)ptr)(elf_hwcap,
		    0, 0, 0, 0, 0, 0, 0);
		*where = target;
		break;
	}
}
#endif
