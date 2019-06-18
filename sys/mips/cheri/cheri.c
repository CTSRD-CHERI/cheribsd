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
#include <sys/cheri_serial.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/atomic.h>
#include <machine/cherireg.h>
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

static union {
	void * __capability	ct_cap;
	uint8_t			ct_bytes[32];
} cheri_testunion __aligned(32);

/*
 * A set of compile-time assertions to ensure suitable alignment for
 * capabilities embedded within other MIPS data structures.  Otherwise changes
 * that work on other architectures might break alignment on CHERI.
 */
CTASSERT(offsetof(struct trapframe, ddc) % CHERICAP_SIZE == 0);
#ifdef COMPAT_CHERIABI
CTASSERT(offsetof(struct mdthread, md_cheri_mmap_cap) % CHERICAP_SIZE == 0);
#endif

/*
 * Ensure that the compiler being used to build the kernel agrees with the
 * kernel configuration on the size of a capability, and that we are compiling
 * for the hybrid ABI.
 */
#ifdef CPU_CHERI128
#ifndef CHERI_PURECAP_KERNEL /* XXX-AM: change to cheri pure capability check */
CTASSERT(sizeof(void *) == 8);
#else
CTASSERT(sizeof(void *) == 16);
#endif
CTASSERT(sizeof(void * __capability) == 16);
CTASSERT(sizeof(struct chericap) == 16);
CTASSERT(sizeof(struct cheri_object) == 32);
#else /* CHERI256 */
#ifndef CHERI_PURECAP_KERNEL
CTASSERT(sizeof(void *) == 8);
#else
CTASSERT(sizeof(void *) == 32);
#endif
CTASSERT(sizeof(void * __capability) == 32);
CTASSERT(sizeof(struct chericap) == 32);
CTASSERT(sizeof(struct cheri_object) == 64);
#endif /* CHERI256 */

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
caddr_t cheri_xuseg_capability;
caddr_t cheri_xkphys_capability;
caddr_t cheri_xkseg_capability;
caddr_t cheri_kseg0_capability;
caddr_t cheri_kseg1_capability;
caddr_t cheri_kseg2_capability;
caddr_t cheri_kcode_capability;
caddr_t cheri_kdata_capability;
caddr_t cheri_kall_capability;

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
			cap = cheri_setoffset(code_cap, reloc->object);
		}
		else {
			if ((reloc->permissions & ELF64_CAPRELOC_RODATA) != 0)
				cap = rodata_cap;
			else
				cap = data_cap;
			cap = cheri_setoffset(cap, reloc->object);
			if (reloc->size != 0)
				cap = cheri_csetbounds(cap, reloc->size);
		}
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
		void **dst = cheri_setoffset(data_cap, reloc->r_offset);

		switch (ELF64_R_TYPE(reloc->r_info)) {
		case R_MIPS_CHERI_CAPABILITY:
			symentry = &dynsym[ELF64_R_SYM(reloc->r_info)];
			if (symentry->st_value == 0) {
				cap = NULL;
			}
			else if (ELF64_ST_TYPE(symentry->st_info) == STT_FUNC) {
				cap = cheri_setoffset(code_cap,
				    symentry->st_value);
			}
			else {
				cap = cheri_setoffset(data_cap,
				    symentry->st_value);
				cap = cheri_csetbounds(cap, symentry->st_size);
			}
			*dst = cap;
			break;
		default:
			panic("Invalid capability relocation");
		}
	}
}

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
cheri_init_capabilities()
{
	void *kdc = cheri_getkdc();

	/*
	 * Split kdc and generate a capability for each memory segment.
	 * XXX-AM: we should also have a separate capability for
	 * KCC that covers only kernel .text and exception vectors
	 * KDC that covers only kernel .data/.rodata/.bss etc.
	 * Those should fall both into kseg0.
	 */
	cheri_xuseg_capability = cheri_csetbounds(
	    cheri_setoffset(kdc, MIPS_XUSEG_START),
	    MIPS_XUSEG_END - MIPS_XUSEG_START);
	cheri_xkphys_capability = cheri_andperm(
	    cheri_csetbounds(cheri_setoffset(kdc, MIPS_XKPHYS_START),
		MIPS_XKPHYS_END - MIPS_XKPHYS_START),
	    (CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP |
	    CHERI_PERM_STORE_CAP | CHERI_PERM_STORE_LOCAL_CAP));
	cheri_xkseg_capability = cheri_csetbounds(
	    cheri_setoffset(kdc, MIPS_XKSEG_START),
	    MIPS_XKSEG_END - MIPS_XKSEG_START);
	cheri_kseg0_capability = cheri_csetbounds(
	    cheri_setoffset(kdc, MIPS_KSEG0_START),
	    (vm_offset_t)MIPS_KSEG0_END - (vm_offset_t)MIPS_KSEG0_START);
	cheri_kseg1_capability = cheri_csetbounds(
	    cheri_setoffset(kdc, MIPS_KSEG1_START),
	    (vm_offset_t)MIPS_KSEG1_END - (vm_offset_t)MIPS_KSEG1_START);
	cheri_kseg2_capability = cheri_csetbounds(
	    cheri_setoffset(kdc, MIPS_KSEG2_START),
	    (vm_offset_t)MIPS_KSEG2_END - (vm_offset_t)MIPS_KSEG2_START);
	cheri_kcode_capability = cheri_andperm(
	    cheri_csetbounds(cheri_setoffset(kdc, MIPS_KSEG0_START),
	    (vm_offset_t)&etext - (vm_offset_t)MIPS_KSEG0_START),
	    (CHERI_PERM_EXECUTE | CHERI_PERM_LOAD | CHERI_PERM_CCALL |
	    CHERI_PERM_SYSTEM_REGS));
	cheri_kdata_capability = cheri_andperm(
	    cheri_csetbounds(cheri_setoffset(kdc, (vm_offset_t)&etext),
	        (vm_offset_t)&end - (vm_offset_t)&etext),
	    ~(CHERI_PERM_EXECUTE | CHERI_PERM_CCALL | CHERI_PERM_SEAL |
	    CHERI_PERM_SYSTEM_REGS));
	cheri_kall_capability = kdc;
}

#endif /* CHERI_PURECAP_KERNEL */

/* Set to -1 to prevent it from being zeroed with the rest of BSS */
void * __capability userspace_cap = (void * __capability)(intcap_t)-1;
void * __capability user_sealcap = (void * __capability)(intcap_t)-1;

/*
 * For now, all we do is declare what we support, as most initialisation took
 * place in the MIPS machine-dependent assembly.  CHERI doesn't need a lot of
 * actual boot-time initialisation.
 */
static void
cheri_cpu_startup(void)
{

	/*
	 * The pragmatic way to test that the kernel we're booting has a
	 * capability size matching the CPU we're booting on is to store a
	 * capability in memory and then check what its footprint was.  Panic
	 * early if our assumptions are wrong.
	 */
	memset(&cheri_testunion, 0xff, sizeof(cheri_testunion));
	cheri_testunion.ct_cap = NULL;
#ifdef CPU_CHERI128
	printf("CHERI: compiled for 128-bit capabilities\n");
	if (cheri_testunion.ct_bytes[16] == 0)
		panic("CPU implements 256-bit capabilities");
#else
	printf("CHERI: compiled for 256-bit capabilities\n");
	if (cheri_testunion.ct_bytes[16] != 0)
		panic("CPU implements 128-bit capabilities");
#endif

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

/*
 * Build a new userspace capability derived from userspace_cap.
 * The resulting capability may include both read and execute permissions,
 * but not write.
 */
void * __capability
_cheri_capability_build_user_code(uint32_t perms, vaddr_t basep, size_t length,
    off_t off, const char* func, int line)
{

	KASSERT((perms & ~CHERI_CAP_USER_CODE_PERMS) == 0,
	    ("%s:%d: perms %x has permission not in CHERI_CAP_USER_CODE_PERMS %x",
	    func, line, perms, CHERI_CAP_USER_CODE_PERMS));

	return (_cheri_capability_build_user_rwx(
	    perms & CHERI_CAP_USER_CODE_PERMS, basep, length, off, func, line));
}

/*
 * Build a new userspace capability derived from userspace_cap.
 * The resulting capability may include read and write permissions, but
 * not execute.
 */
void * __capability
_cheri_capability_build_user_data(uint32_t perms, vaddr_t basep, size_t length,
    off_t off, const char* func, int line)
{

	KASSERT((perms & ~CHERI_CAP_USER_DATA_PERMS) == 0,
	    ("%s:%d: perms %x has permission not in CHERI_CAP_USER_DATA_PERMS %x",
	    func, line, perms, CHERI_CAP_USER_DATA_PERMS));

	return (_cheri_capability_build_user_rwx(
	    perms & CHERI_CAP_USER_DATA_PERMS, basep, length, off, func, line));
}

/*
 * Build a new userspace capability derived from userspace_cap.
 * The resulting capability may include read, write, and execute permissions.
 *
 * This function violates W^X and its use is discouraged and the reason for
 * use should be documented in a comment when it is used.
 */
void * __capability
_cheri_capability_build_user_rwx(uint32_t perms, vaddr_t basep, size_t length,
    off_t off, const char* func __unused, int line __unused)
{
	void * __capability tmpcap;

	tmpcap = cheri_setoffset(cheri_andperm(cheri_csetbounds(
	    cheri_setoffset(userspace_cap, basep), length), perms), off);

	KASSERT(cheri_getlen(tmpcap) == length,
	    ("%s:%d: Constructed capability has wrong length 0x%zx != 0x%zx: "
	    _CHERI_PRINTF_CAP_FMT, func, line, cheri_getlen(tmpcap), length,
	    _CHERI_PRINTF_CAP_ARG(tmpcap)));

	return (tmpcap);
}

void
cheri_capability_set_user_sigcode(void * __capability *cp,
    struct sysentvec *se)
{
	uintptr_t base;
	int szsigcode = *se->sv_szsigcode;

	if (se->sv_sigcode_base != 0) {
		base = se->sv_sigcode_base;
	} else {
		/*
		 * XXX: true for mips64 and mip64-cheriabi without shared-page
		 * support...
		 */
		base = (uintptr_t)se->sv_psstrings - szsigcode;
		base = rounddown2(base, sizeof(struct chericap));
	}

	*cp = cheri_capability_build_user_code(CHERI_CAP_USER_CODE_PERMS,
	    base, szsigcode, 0);
}

void
cheri_capability_set_user_sealcap(void * __capability *cp)
{

	*cp = user_sealcap;
}

void
cheri_serialize(struct cheri_serial *csp, void * __capability cap)
{

#if CHERICAP_SIZE == 16
	csp->cs_storage = 3;
	csp->cs_typebits = 16;
	csp->cs_permbits = 23;
#else /* CHERICAP_SIZE == 32 */
	csp->cs_storage = 4;
	csp->cs_typebits = 24;
	csp->cs_permbits = 31;
#endif

	KASSERT(csp != NULL, ("Can't serialize to a NULL pointer"));
	if (cap == NULL) {
		memset(csp, 0, sizeof(*csp));
		return;
	}

	csp->cs_tag = __builtin_cheri_tag_get(cap);
	if (csp->cs_tag) {
		csp->cs_type = __builtin_cheri_type_get(cap);
		csp->cs_perms = __builtin_cheri_perms_get(cap);
		csp->cs_sealed = __builtin_cheri_sealed_get(cap);
		csp->cs_base = __builtin_cheri_base_get(cap);
		csp->cs_length = __builtin_cheri_length_get(cap);
		csp->cs_offset = __builtin_cheri_offset_get(cap);
	} else
		memcpy(&csp->cs_data, &cap, CHERICAP_SIZE);
}
// CHERI CHANGES START
// {
//   "updated": 20190605,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
