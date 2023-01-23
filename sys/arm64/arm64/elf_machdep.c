/*-
 * Copyright (c) 2014, 2015 The FreeBSD Foundation.
 * Copyright (c) 2014 Andrew Turner.
 * All rights reserved.
 *
 * This software was developed by Andrew Turner under
 * sponsorship from the FreeBSD Foundation.
 *
 * Portions of this software were developed by Konstantin Belousov
 * under sponsorship from the FreeBSD Foundation.
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
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/linker.h>
#include <sys/proc.h>
#include <sys/reg.h>
#include <sys/sysent.h>
#include <sys/imgact_elf.h>
#include <sys/syscall.h>
#include <sys/signalvar.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_param.h>

#include <machine/elf.h>
#include <machine/md_var.h>

#include "linker_if.h"

#ifdef CHERI_CAPREVOKE
#include <cheri/revoke.h>
#include <vm/vm_cheri_revoke.h>
#endif

u_long __read_frequently elf_hwcap;
u_long __read_frequently elf_hwcap2;

struct arm64_addr_mask elf64_addr_mask;

static struct sysentvec elf64_freebsd_sysvec = {
	.sv_size	= SYS_MAXSYSCALL,
	.sv_table	= sysent,
	.sv_fixup	= __elfN(freebsd_fixup),
	.sv_sendsig	= sendsig,
	.sv_sigcode	= sigcode,
	.sv_szsigcode	= &szsigcode,
#if __has_feature(capabilities)
	.sv_name	= "FreeBSD ELF64C",	/* CheriABI */
#else
	.sv_name	= "FreeBSD ELF64",
#endif
	.sv_coredump	= __elfN(coredump),
	.sv_elf_core_osabi = ELFOSABI_FREEBSD,
	.sv_elf_core_abi_vendor = FREEBSD_ABI_VENDOR,
	.sv_elf_core_prepare_notes = __elfN(prepare_notes),
	.sv_imgact_try	= NULL,
	.sv_minsigstksz	= MINSIGSTKSZ,
	.sv_minuser	= VM_MIN_ADDRESS,
	.sv_maxuser	= VM_MAXUSER_ADDRESS,
	.sv_usrstack	= USRSTACK,
	.sv_psstringssz	= sizeof(struct ps_strings),
	.sv_stackprot	= VM_PROT_RW_CAP,
	.sv_copyout_auxargs = __elfN(freebsd_copyout_auxargs),
	.sv_copyout_strings = exec_copyout_strings,
	.sv_setregs	= exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_SHP | SV_TIMEKEEP | SV_ABI_FREEBSD | SV_LP64 |
	    SV_RNG_SEED_VER |
#if __has_feature(capabilities)
	    SV_CHERI,
#else
	    SV_ASLR,
#endif
	.sv_set_syscall_retval = cpu_set_syscall_retval,
	.sv_fetch_syscall_args = cpu_fetch_syscall_args,
	.sv_syscallnames = syscallnames,
	.sv_shared_page_base = SHAREDPAGE,
	.sv_shared_page_len = PAGE_SIZE,
	.sv_schedtail	= NULL,
	.sv_thread_detach = NULL,
	.sv_trap	= NULL,
	.sv_hwcap	= &elf_hwcap,
	.sv_hwcap2	= &elf_hwcap2,
	.sv_onexec_old	= exec_onexec_old,
	.sv_onexit	= exit_onexit,
	.sv_regset_begin = SET_BEGIN(__elfN(regset)),
	.sv_regset_end	= SET_LIMIT(__elfN(regset)),
};
INIT_SYSENTVEC(elf64_sysvec, &elf64_freebsd_sysvec);

#ifdef CHERI_CAPREVOKE
static void
caprevoke_sysvec_init(void *arg)
{
	struct sysentvec *sv = arg;

	/*
	 * How big do we need the fine-grained memory shadow bitmap to be?  This
	 * will be 1 << 41 since VM_MAX_USER_ADDRESS is 1 << 48.
	 */
	const size_t shadow_fine_mem_size =
	    sv->sv_maxuser / 8 / VM_CHERI_REVOKE_GSZ_MEM_NOMAP;

	/* Land the shadow somewhere awkward but easy */
	const vaddr_t shadow_fine_mem_top =
	    sv->sv_usrstack & ~(shadow_fine_mem_size - 1);

	/*
	 * The coarse-grained memory bitmap will be either 1 << 33.
	 */
	const size_t shadow_coarse_mem_size =
	    sv->sv_maxuser / 8 / VM_CHERI_REVOKE_GSZ_MEM_MAP;

	const size_t shadow_required_size = shadow_fine_mem_size
	    + shadow_coarse_mem_size
	    + VM_CHERI_REVOKE_BSZ_OTYPE;

	const size_t shadow_representable_size =
	    CHERI_REPRESENTABLE_LENGTH(shadow_required_size);

	sv->sv_cheri_revoke_shadow_length = shadow_representable_size;
	sv->sv_cheri_revoke_shadow_base =
	    shadow_fine_mem_top - shadow_representable_size;

	/*
	 * This places the fine-grained memory bitmap at the top, and so
	 * naturally aligned, region within the representation-padded region
	 * just defined.
	 */
	sv->sv_cheri_revoke_shadow_offset =
	    shadow_representable_size - shadow_fine_mem_size;

	/* It's ugly, but simple: manage the info page as a separate object */
	sv->sv_cheri_revoke_info_page =
	    sv->sv_cheri_revoke_shadow_base - PAGE_SIZE;
}
SYSINIT(caprevoke_sysvec, SI_SUB_VM, SI_ORDER_ANY, caprevoke_sysvec_init,
    &elf64_freebsd_sysvec);
#endif

static __ElfN(Brandinfo) freebsd_brand_info = {
	.brand		= ELFOSABI_FREEBSD,
	.machine	= EM_AARCH64,
	.compat_3_brand	= "FreeBSD",
	.emul_path	= NULL,
	.interp_path	= "/libexec/ld-elf.so.1",
	.sysvec		= &elf64_freebsd_sysvec,
#if __has_feature(capabilities)
	.interp_newpath	= "/libexec/ld-elf64c.so.1",
#else
	.interp_newpath	= NULL,
#endif
	.brand_note	= &__elfN(freebsd_brandnote),
	.flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE
};

SYSINIT(elf64, SI_SUB_EXEC, SI_ORDER_FIRST,
    (sysinit_cfunc_t)__elfN(insert_brand_entry), &freebsd_brand_info);

static bool
get_arm64_addr_mask(struct regset *rs, struct thread *td, void *buf,
    size_t *sizep)
{
	if (buf != NULL) {
		KASSERT(*sizep == sizeof(elf64_addr_mask),
		    ("%s: invalid size", __func__));
		memcpy(buf, &elf64_addr_mask, sizeof(elf64_addr_mask));
	}
	*sizep = sizeof(elf64_addr_mask);

	return (true);
}

struct regset regset_arm64_addr_mask = {
	.note = NT_ARM_ADDR_MASK,
	.size = sizeof(struct arm64_addr_mask),
	.get = get_arm64_addr_mask,
};
ELF_REGSET(regset_arm64_addr_mask);

void
__elfN(dump_thread)(struct thread *td __unused, void *dst __unused,
    size_t *off __unused)
{
}

bool
elf_is_ifunc_reloc(Elf_Size r_info __unused)
{

	return (ELF_R_TYPE(r_info) == R_AARCH64_IRELATIVE ||
	    ELF_R_TYPE(r_info) == R_MORELLO_IRELATIVE);
}

static int
reloc_instr_imm(Elf32_Addr *where, Elf_Addr val, u_int msb, u_int lsb)
{

	/* Check bounds: upper bits must be all ones or all zeros. */
	if ((uint64_t)((int64_t)val >> (msb + 1)) + 1 > 1)
		return (-1);
	val >>= lsb;
	val &= (1 << (msb - lsb + 1)) - 1;
	*where |= (Elf32_Addr)val;
	return (0);
}

#if __has_feature(capabilities)
static uintcap_t __nosanitizecoverage
build_cap_from_fragment(Elf_Addr *fragment, Elf_Addr relocbase,
    Elf_Addr offset, void * __capability data_cap,
    const void * __capability code_cap)
{
	Elf_Addr addr, size;
	uint8_t perms;
	uintcap_t cap;

	addr = fragment[0];
	size = fragment[1] & ((1UL << (8 * sizeof(Elf_Addr) - 8)) - 1);
	perms = fragment[1] >> (8 * sizeof(Elf_Addr) - 8);

	cap = perms == MORELLO_FRAG_EXECUTABLE ?
	    (uintcap_t)code_cap : (uintcap_t)data_cap;
	cap = cheri_setaddress(cap, relocbase + addr);

	if (perms == MORELLO_FRAG_EXECUTABLE ||
	    perms == MORELLO_FRAG_RODATA) {
		cap = cheri_clearperm(cap, CHERI_PERM_SEAL |
		    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		    CHERI_PERM_STORE_LOCAL_CAP);
	}
	if (perms == MORELLO_FRAG_RWDATA ||
	    perms == MORELLO_FRAG_RODATA) {
		cap = cheri_clearperm(cap, CHERI_PERM_SEAL |
		    CHERI_PERM_EXECUTE);
		cap = cheri_setbounds(cap, size);
	}
	cap += offset;
	if (perms == MORELLO_FRAG_EXECUTABLE) {
		cap = cheri_sealentry(cap);
	}
	KASSERT(cheri_gettag(cap) != 0,
	    ("Relocation produce invalid capability %#lp",
	    (void * __capability)cap));
	return (cap);
}
#endif

/*
 * Process a relocation.  Support for some static relocations is required
 * in order for the -zifunc-noplt optimization to work.
 */
static int
elf_reloc_internal(linker_file_t lf, char *relocbase, const void *data,
    int type, int flags, elf_lookup_fn lookup)
{
#define	ARM64_ELF_RELOC_LOCAL		(1 << 0)
#define	ARM64_ELF_RELOC_LATE_IFUNC	(1 << 1)
	Elf_Addr *where, addr, addend;
#if __has_feature(capabilities)
	uintcap_t cap;
#endif
#ifndef __CHERI_PURE_CAPABILITY__
	Elf_Addr val;
#endif
	Elf_Word rtype, symidx;
	const Elf_Rel *rel;
	const Elf_Rela *rela;
	int error;

	switch (type) {
	case ELF_RELOC_REL:
		rel = (const Elf_Rel *)data;
		where = (Elf_Addr *) (relocbase + rel->r_offset);
		addend = *where;
		rtype = ELF_R_TYPE(rel->r_info);
		symidx = ELF_R_SYM(rel->r_info);
		break;
	case ELF_RELOC_RELA:
		rela = (const Elf_Rela *)data;
		where = (Elf_Addr *) (relocbase + rela->r_offset);
		addend = rela->r_addend;
		rtype = ELF_R_TYPE(rela->r_info);
		symidx = ELF_R_SYM(rela->r_info);
		break;
	default:
		panic("unknown reloc type %d\n", type);
	}

	if ((flags & ARM64_ELF_RELOC_LATE_IFUNC) != 0) {
		KASSERT(type == ELF_RELOC_RELA,
		    ("Only RELA ifunc relocations are supported"));
		/*
		 * NB: We do *not* re-process R_MORELLO_IRELATIVE since the
		 * normal pass has already trashed the fragment and so we no
		 * longer know what the resolver is, just like architectures
		 * that use REL instead of RELA.
		 */
		if (rtype != R_AARCH64_IRELATIVE)
			return (0);
	}

	if ((flags & ARM64_ELF_RELOC_LOCAL) != 0) {
		if (rtype == R_AARCH64_RELATIVE)
			*where = elf_relocaddr(lf, (Elf_Addr)relocbase + addend);
#if __has_feature(capabilities)
		else if (rtype == R_MORELLO_RELATIVE) {
			cap = build_cap_from_fragment(where,
			    (Elf_Addr)relocbase, addend,
			    (__cheri_tocap void * __capability)relocbase,
			    (__cheri_tocap void * __capability)relocbase);
			*(uintcap_t *)(void *)where = cap;
		}
#endif
		return (0);
	}

	error = 0;
	switch (rtype) {
	case R_AARCH64_NONE:
	case R_AARCH64_RELATIVE:
		break;
	case R_AARCH64_TSTBR14:
		error = lookup(lf, symidx, 1, &addr);
		if (error != 0)
			return (-1);
		error = reloc_instr_imm((Elf32_Addr *)where,
		    addr + addend - (Elf_Addr)where, 15, 2);
		break;
	case R_AARCH64_CONDBR19:
		error = lookup(lf, symidx, 1, &addr);
		if (error != 0)
			return (-1);
		error = reloc_instr_imm((Elf32_Addr *)where,
		    addr + addend - (Elf_Addr)where, 20, 2);
		break;
	case R_AARCH64_JUMP26:
	case R_AARCH64_CALL26:
		error = lookup(lf, symidx, 1, &addr);
		if (error != 0)
			return (-1);
		error = reloc_instr_imm((Elf32_Addr *)where,
		    addr + addend - (Elf_Addr)where, 27, 2);
		break;
	case R_AARCH64_ABS64:
	case R_AARCH64_GLOB_DAT:
	case R_AARCH64_JUMP_SLOT:
		error = lookup(lf, symidx, 1, &addr);
		if (error != 0)
			return (-1);
		*where = addr + addend;
		break;
	case R_AARCH64_IRELATIVE:
#ifdef __CHERI_PURE_CAPABILITY__
		printf("kldload: AARCH64_IRELATIVE relocation should not "
		    "exist in purecap CHERI kernel modules\n");
		return (-1);
#else
		addr = (Elf_Addr)relocbase + addend;
		val = ((Elf64_Addr (*)(void))addr)();
		if (*where != val)
			*where = val;
#endif
		break;
#if __has_feature(capabilities)
	case R_MORELLO_RELATIVE:
		break;
#ifdef __CHERI_PURE_CAPABILITY__
	case R_MORELLO_CAPINIT:
	case R_MORELLO_GLOB_DAT:
		error = LINKER_SYMIDX_CAPABILITY(lf, symidx, 1, &cap);
		if (error != 0)
			return (-1);
		cap += addend;
		*(uintcap_t *)where = cap;
		break;
	case R_MORELLO_JUMP_SLOT:
		error = LINKER_SYMIDX_CAPABILITY(lf, symidx, 1, &cap);
		if (error != 0)
			return (-1);
		cap = cheri_clearperm(cap, CHERI_PERM_SEAL |
		    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		    CHERI_PERM_STORE_LOCAL_CAP);
		*(uintcap_t *)where = cheri_sealentry(cap);
		break;
	case R_MORELLO_IRELATIVE:
		/* XXX: See libexec/rtld-elf/aarch64/reloc.c. */
		if ((where[0] == 0 && where[1] == 0) ||
		    (Elf_Ssize)where[0] == rela->r_addend) {
			cap = (uintptr_t)(relocbase + rela->r_addend);
			cap = cheri_clearperm(cap, CHERI_PERM_SEAL |
			    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
			    CHERI_PERM_STORE_LOCAL_CAP);
			cap = cheri_sealentry(cap);
		} else
			cap = build_cap_from_fragment(where,
			    (Elf_Addr)relocbase, rela->r_addend,
			    relocbase, relocbase);
		cap = ((uintptr_t (*)(void))cap)();
		*(uintcap_t *)where = cap;
		break;
#endif
#endif
	default:
		printf("kldload: unexpected relocation type %d, "
		    "symbol index %d\n", rtype, symidx);
		return (-1);
	}
	return (error);
}

int
elf_reloc_local(linker_file_t lf, char *relocbase, const void *data,
    int type, elf_lookup_fn lookup)
{

	return (elf_reloc_internal(lf, relocbase, data, type,
	    ARM64_ELF_RELOC_LOCAL, lookup));
}

/* Process one elf relocation with addend. */
int
elf_reloc(linker_file_t lf, char *relocbase, const void *data, int type,
    elf_lookup_fn lookup)
{

	return (elf_reloc_internal(lf, relocbase, data, type, 0, lookup));
}

int
elf_reloc_late(linker_file_t lf, char *relocbase, const void *data,
    int type, elf_lookup_fn lookup)
{

	return (elf_reloc_internal(lf, relocbase, data, type,
	    ARM64_ELF_RELOC_LATE_IFUNC, lookup));
}

int
elf_cpu_load_file(linker_file_t lf)
{

	if (lf->id != 1)
		cpu_icache_sync_range((vm_pointer_t)lf->address, lf->size);
	return (0);
}

int
elf_cpu_unload_file(linker_file_t lf __unused)
{

	return (0);
}

int
elf_cpu_parse_dynamic(caddr_t loadbase __unused, Elf_Dyn *dynamic __unused)
{

	return (0);
}

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * Handle boot-time kernel relocations, this is called by locore.
 */
void __nosanitizecoverage
elf_reloc_self(const Elf_Dyn *dynp, void *data_cap, const void *code_cap)
{
	const Elf_Rela *rela = NULL, *rela_end;
	Elf_Addr *fragment;
	uintptr_t cap;
	size_t rela_size = 0;

	for (; dynp->d_tag != DT_NULL; dynp++) {
		switch (dynp->d_tag) {
		case DT_RELA:
			rela = (const Elf_Rela *)((const char *)data_cap +
			    dynp->d_un.d_ptr);
			break;
		case DT_RELASZ:
			rela_size = dynp->d_un.d_val;
			break;
		}
	}

	rela = cheri_setbounds(rela, rela_size);
	rela_end = (const Elf_Rela *)((const char *)rela + rela_size);

	for (; rela < rela_end; rela++) {
		/* Can not panic yet */
		if (ELF_R_TYPE(rela->r_info) != R_MORELLO_RELATIVE)
			continue;

		fragment = (Elf_Addr *)((char *)data_cap + rela->r_offset);
		cap = build_cap_from_fragment(fragment, 0, rela->r_addend,
		    data_cap, code_cap);
		*((uintptr_t *)fragment) = cap;
	}
}
#endif
// CHERI CHANGES START
// {
//   "updated": 20221129,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support",
//     "pointer_as_integer"
//   ]
// }
// CHERI CHANGES END
