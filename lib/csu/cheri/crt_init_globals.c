/*-
 * Copyright (c) 2014 Robert N. M. Watson
 * Copyright (c) 2017-2018 Alex Richardson
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
#include <sys/cdefs.h>
#include <stdint.h>
#include <stdlib.h>

void crt_init_globals(void) __hidden;

struct capreloc
{
	uint64_t capability_location;
	uint64_t object;
	uint64_t offset;
	uint64_t size;
	uint64_t permissions;
};
static const uint64_t function_reloc_flag = 1ULL<<63;
static const uint64_t function_pointer_permissions =
	~0 &
	~__CHERI_CAP_PERMISSION_PERMIT_STORE_CAPABILITY__ &
	~__CHERI_CAP_PERMISSION_PERMIT_STORE__;
static const uint64_t global_pointer_permissions =
	~0 & ~__CHERI_CAP_PERMISSION_PERMIT_EXECUTE__;

__attribute__((weak))
extern struct capreloc __start___cap_relocs;
__attribute__((weak))
extern struct capreloc __stop___cap_relocs;

__attribute__((weak)) extern int _DYNAMIC;

void
crt_init_globals(void)
{
#ifdef PCREL_SYMBOL_ADDRESSES_WORK
	void* _pcc_after_daddui = 0;
	int64_t _dynamic_pcrel = 0;
	/*
	 * We can't get the address of _DYNAMIC in the purecap ABI before globals
	 * are initialized so we need to use dla here. If _DYNAMIC exists
	 * then the runtime-linker will have done the __cap_relocs already
	 * so we should be processing them here. Furthermore it will also have
	 * enforced relro so we will probably crash when attempting to write
	 * const pointers that are initialized to global addresses.
	 *
	 * TODO: Maybe clang should provide a __builtin_symbol_address() that is
	 * always filled in a static link time...
	 */
	__asm__ volatile(".global _DYNAMIC\n\t"
	    /*
	     * XXXAR: For some reason the attribute weak above is ignored if we
	     * don't also include it in the inline assembly
	     */
	    ".weak _DYNAMIC\n\t"
	    "lui %0, %%pcrel_hi(_DYNAMIC - 8)\n\t"
	    "daddiu %0, %0, %%pcrel_lo(_DYNAMIC - 4)\n\t"
	    "cgetpcc %1\n\t"
	    : "+r"(_dynamic_pcrel), "+C"(_pcc_after_daddui));

	/*
	 * If the address of _DYNAMIC is non-zero then we are dynamically linked
	 * and RTLD will be responsible for processing the capability relocs
	 * FIXME: MIPS only has 32-bit pcrelative relocations so this overflows
	 * For now just assume that if the pcrel value is greater than INT_MAX
	 * the value of _DYNAMIC is zero
	 */
	if ((vaddr_t)_pcc_after_daddui + _dynamic_pcrel != 0 &&
	    labs(_dynamic_pcrel) <= (int64_t)INT32_MAX)
		return;
#else
	/*
	 * XXXAR: Since the MIPS %pcrel doesn't appear to work to get the value
	 * of _DYNAMIC without a text relocation I changed LLD to emit a symbol
	 * _HAS__DYNAMIC instead. This also has the advantage that it only needs
	 * a single instruction to load rather than the full dla/pcrel sequence.
	 */
	int64_t _has__DYNAMIC;
	__asm__ volatile(".global _DYNAMIC\n\t"
	    /*
	     * XXXAR: For some reason the attribute weak above is ignored if we
	     * don't also include it in the inline assembly
	     */
	    ".weak _DYNAMIC\n\t"
	    "ori %0, $zero, %%lo(_HAS__DYNAMIC)\n\t"
	    : "+r"(_has__DYNAMIC));
	/* If we are dynamically linked, the runtime linker takes care of this */
	if (_has__DYNAMIC)
		return;
#endif

	void *gdc = __builtin_cheri_global_data_get();
	void *pcc = __builtin_cheri_program_counter_get();

	gdc = __builtin_cheri_perms_and(gdc, global_pointer_permissions);
	pcc = __builtin_cheri_perms_and(pcc, function_pointer_permissions);
	for (struct capreloc *reloc = &__start___cap_relocs ;
	     reloc < &__stop___cap_relocs ; reloc++)
	{
		_Bool isFunction = (reloc->permissions & function_reloc_flag) ==
			function_reloc_flag;
		void **dest = __builtin_cheri_offset_set(gdc, reloc->capability_location);
		void *base = isFunction ? pcc : gdc;
		void *src = __builtin_cheri_offset_set(base, reloc->object);
		if (!isFunction && (reloc->size != 0))
		{
			src = __builtin_cheri_bounds_set(src, reloc->size);
		}
		src = __builtin_cheri_offset_increment(src, reloc->offset);
		*dest = src;
	}
}
