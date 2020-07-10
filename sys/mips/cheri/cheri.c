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
#include <sys/sysctl.h>
#include <sys/sysent.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/atomic.h>
#include <machine/pcb.h>
#include <machine/proc.h>
#include <machine/sysarch.h>
#include <machine/vmparam.h>

CTASSERT(sizeof(void * __capability) == CHERICAP_SIZE);
/* 33 capability registers + capcause + capvalid + padding. */
CTASSERT(sizeof(struct cheri_frame) == (34 * CHERICAP_SIZE));

/*
 * Beginnings of a programming interface for explicitly managing capability
 * registers.  Convert back and forth between capability registers and
 * general-purpose registers/memory so that we can program the context,
 * save/restore application contexts, etc.
 *
 * In the future, we'd like the compiler to do this sort of stuff for us
 * based on language-level properties and annotations, but in the mean
 * time...
 *
 * XXXRW: Any manipulation of $ddc should include a "memory" clobber for inline
 * assembler, so that the compiler will write back memory contents before the
 * call, and reload them afterwards.
 */

/*
 * A set of compile-time assertions to ensure suitable alignment for
 * capabilities embedded within other MIPS data structures.  Otherwise changes
 * that work on other architectures might break alignment on CHERI.
 */
CTASSERT(offsetof(struct trapframe, ddc) % CHERICAP_SIZE == 0);
CTASSERT(offsetof(struct thread, td_cheri_mmap_cap) % CHERICAP_SIZE == 0);

/*
 * Ensure that the compiler being used to build the kernel agrees with the
 * kernel configuration on the size of a capability, and that we are compiling
 * for the hybrid or pure ABI.
 */
#ifndef CHERI_PURECAP_KERNEL
CTASSERT(sizeof(void *) == 8);
#else
CTASSERT(sizeof(void *) == 16);
#endif
CTASSERT(sizeof(void * __capability) == 16);
CTASSERT(sizeof(struct cheri_object) == 32);

/* Set to -1 to prevent it from being zeroed with the rest of BSS */
void * __capability user_sealcap = (void * __capability)(intcap_t)-1;

#ifdef CHERI_PURECAP_KERNEL
__attribute__((weak))
extern Elf64_Capreloc __start___cap_relocs;
__attribute__((weak))
extern Elf64_Capreloc __stop___cap_relocs;

/* Defined in linker script, mark the end of .text and kernel image */
extern char etext[], end[];

/*
 * Global capabilities for various address-space segments.
 */
caddr_t cheri_xkphys_capability = (void *)(intcap_t)-1;
caddr_t cheri_xkseg_capability = (void *)(intcap_t)-1;
caddr_t cheri_kseg0_capability = (void *)(intcap_t)-1;
caddr_t cheri_kseg1_capability = (void *)(intcap_t)-1;
caddr_t cheri_kseg2_capability = (void *)(intcap_t)-1;
caddr_t cheri_kcode_capability = (void *)(intcap_t)-1;
caddr_t cheri_kdata_capability = (void *)(intcap_t)-1;
void *cheri_kall_capability = (void *)(intcap_t)-1;

/*
 * This is called from locore to initialise the cap table entries
 * and other capability relocations.
 */
void
process_kernel_cap_relocs(Elf64_Capreloc *start, Elf64_Capreloc *end,
    void *code_cap, void *data_cap)
{
	void *rodata_cap = cheri_andperm(data_cap, CHERI_PERMS_KERNEL);

	code_cap = cheri_andperm(code_cap, CHERI_PERMS_KERNEL_CODE);
	data_cap = cheri_andperm(data_cap, CHERI_PERMS_KERNEL_DATA);

	for (Elf64_Capreloc *reloc = start; reloc < end; reloc++) {
		void *cap;
		void **dst = cheri_setoffset(data_cap, reloc->location);

		if ((reloc->permissions & ELF64_CAPRELOC_FUNCTION) != 0) {
			cap = cheri_setaddress(code_cap, reloc->object);
		}
		else {
			if ((reloc->permissions & ELF64_CAPRELOC_RODATA) != 0)
				cap = rodata_cap;
			else
				cap = data_cap;
			cap = cheri_setaddress(cap, reloc->object);
		}
		/*
		 * XXX-AM: do not set 0 bounds, this is a workaround to make
		 * branches across exception handlers work without changes.
		 * Should probably go away at some point.
		 */
		if (reloc->size != 0)
			cap = cheri_setbounds(cap, reloc->size);
		cap = cheri_incoffset(cap, reloc->offset);
		*dst = cap;
	}
}

/*
 * This is called from locore to initialize capability function pointers.
 * In the PLT ABI function pointers use R_MIPS_CHERI_CAPABILITY entries.
 */
void
process_kernel_dyn_relocs(Elf64_Rel *start, Elf64_Rel *end,
    Elf64_Sym *dynsym, void *code_cap, void *data_cap)
{
	code_cap = cheri_andperm(code_cap, CHERI_PERMS_KERNEL_CODE);
	data_cap = cheri_andperm(data_cap, CHERI_PERMS_KERNEL_DATA);

	for (Elf64_Rel *reloc = start; reloc < end; reloc++) {
		void *cap;
		Elf64_Sym *symentry;
		void **dst = cheri_setaddress(data_cap, reloc->r_offset);

		switch (ELF64_R_TYPE(reloc->r_info)) {
		case R_MIPS_CHERI_CAPABILITY:
			symentry = &dynsym[ELF64_R_SYM(reloc->r_info)];
			if (symentry->st_value == 0) {
				cap = NULL;
			}
			else if (ELF64_ST_TYPE(symentry->st_info) == STT_FUNC) {
				cap = cheri_setaddress(code_cap,
				    symentry->st_value);
				/*
				 * XXX-AM: do not set 0 bounds, this is a workaround to make
				 * branches across exception handlers work without changes.
				 * Should probably go away at some point.
				 */
				if (symentry->st_size != 0)
				  cap = cheri_setbounds(cap, symentry->st_size);
			}
			else {
				cap = cheri_setaddress(data_cap,
				    symentry->st_value);
				cap = cheri_setbounds(cap, symentry->st_size);
			}
			*dst = cap;
			break;
		default:
			panic("Invalid capability relocation");
		}
	}
}
#endif /* CHERI_PURECAP_KERNEL */

/*
 * Early capability initialization.
 * Process capability relocations and initialize
 * kernel segment capabilities.
 *
 * Note this must be called before accessing any global
 * pointer. And after clearing .bss and .sbss because
 * it stores data in those sections.
 */
void
cheri_init_capabilities(void * __capability kroot)
{
	void * __capability ctemp;

	/* Create a capability for userspace to seal capabilities with. */
	ctemp = cheri_setaddress(kroot, CHERI_SEALCAP_USERSPACE_BASE);
	ctemp = cheri_setbounds(ctemp, CHERI_SEALCAP_USERSPACE_LENGTH);
	ctemp = cheri_andperm(ctemp, CHERI_SEALCAP_USERSPACE_PERMS);
	user_sealcap = ctemp;

	ctemp = cheri_setaddress(kroot, CHERI_CAP_USER_DATA_BASE);
	ctemp = cheri_setbounds(ctemp, CHERI_CAP_USER_DATA_LENGTH);
	ctemp = cheri_andperm(ctemp, CHERI_CAP_USER_DATA_PERMS |
	    CHERI_CAP_USER_CODE_PERMS);
	userspace_cap = ctemp;

#ifdef CHERI_PURECAP_KERNEL
	/*
	 * Split kroot and generate a capability for each memory segment.
	 * XXX-AM: we should also have a separate capability for
	 * KCC that covers only kernel .text and exception vectors
	 * KROOT that covers only kernel .data/.rodata/.bss etc.
	 * Those should fall both into kseg0.
	 */
	cheri_xkphys_capability = cheri_ptrperm(
	    cheri_setoffset(kroot, MIPS_XKPHYS_START),
	    MIPS_XKPHYS_END - MIPS_XKPHYS_START,
	    (CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP |
	     CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP));
	cheri_xkseg_capability = cheri_ptrperm(
	    cheri_setoffset(kroot, MIPS_XKSEG_START),
	    MIPS_XKSEG_END - MIPS_XKSEG_START,
	    CHERI_CAP_KERN_PERMS);
	cheri_kseg0_capability = cheri_ptrperm(
	    cheri_setoffset(kroot, MIPS_KSEG0_START),
	    (vaddr_t)MIPS_KSEG0_END - (vaddr_t)MIPS_KSEG0_START,
	    CHERI_CAP_KERN_PERMS);
	cheri_kseg1_capability = cheri_ptrperm(
	    cheri_setoffset(kroot, MIPS_KSEG1_START),
	    (vaddr_t)MIPS_KSEG1_END - (vaddr_t)MIPS_KSEG1_START,
	    CHERI_CAP_KERN_PERMS);
	cheri_kseg2_capability = cheri_ptrperm(
	    cheri_setoffset(kroot, MIPS_KSEG2_START),
	    (vaddr_t)MIPS_KSEG2_END - (vaddr_t)MIPS_KSEG2_START,
	    CHERI_CAP_KERN_PERMS);

	ctemp = cheri_setoffset(kroot, MIPS_KSEG0_START);
	ctemp = cheri_setboundsexact(ctemp,
	    (vaddr_t)&etext - (vaddr_t)MIPS_KSEG0_START);
	cheri_kcode_capability = cheri_andperm(ctemp,
	    (CHERI_PERM_EXECUTE | CHERI_PERM_LOAD | CHERI_PERM_CCALL |
	     CHERI_PERM_SYSTEM_REGS | CHERI_PERM_GLOBAL));

	ctemp = cheri_setoffset(kroot, (vaddr_t)&etext);
	ctemp = cheri_setboundsexact(ctemp,
	    (vaddr_t)&end - (vaddr_t)&etext);
	cheri_kdata_capability = cheri_andperm(ctemp,
	    ~(CHERI_PERM_EXECUTE | CHERI_PERM_CCALL | CHERI_PERM_SEAL |
	      CHERI_PERM_SYSTEM_REGS));

	cheri_kall_capability = kroot;
#endif
}

/*
 * For now, all we do is declare what we support, as most initialisation took
 * place in the MIPS machine-dependent assembly.  CHERI doesn't need a lot of
 * actual boot-time initialisation.
 */
static void
cheri_cpu_startup(void)
{

	/*
	 * Documentary assertions for userspace_cap.  Default data and
	 * code need to be identically sized or we'll need seperate caps.
	 */
	_Static_assert(CHERI_CAP_USER_DATA_BASE == CHERI_CAP_USER_CODE_BASE,
	    "Code and data bases differ");
	_Static_assert(CHERI_CAP_USER_DATA_LENGTH == CHERI_CAP_USER_CODE_LENGTH,
	    "Code and data lengths differ");
	_Static_assert(CHERI_CAP_USER_DATA_OFFSET == 0,
	    "Data offset is non-zero");
	_Static_assert(CHERI_CAP_USER_CODE_OFFSET == 0,
	    "Code offset is non-zero");

	/*
	 * XXX-BD: KDC may now be reduced.
	 */
}
SYSINIT(cheri_cpu_startup, SI_SUB_CPU, SI_ORDER_FIRST, cheri_cpu_startup,
    NULL);

void
cheri_capability_set_user_sealcap(void * __capability *cp)
{

	*cp = user_sealcap;
}
// CHERI CHANGES START
// {
//   "updated": 20200429,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
