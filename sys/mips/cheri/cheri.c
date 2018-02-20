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
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/unistd.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/atomic.h>
#include <machine/cherireg.h>
#include <machine/pcb.h>
#include <machine/proc.h>
#include <machine/sysarch.h>
#include <machine/md_var.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_map.h>

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
CTASSERT(offsetof(struct mdthread, md_tls_cap) % CHERICAP_SIZE == 0);
CTASSERT(offsetof(struct mdthread, md_cheri_mmap_cap) % CHERICAP_SIZE == 0);

/*
 * Ensure that the compiler being used to build the kernel agrees with the
 * kernel configuration on the size of a capability, and that we are compiling
 * for the hybrid ABI.
 */
#ifdef CPU_CHERI128
CTASSERT(sizeof(void *) == 8);
CTASSERT(sizeof(void *__capability) == 16);
CTASSERT(sizeof(struct chericap) == 16);
CTASSERT(sizeof(struct cheri_object) == 32);
#else
CTASSERT(sizeof(void *) == 8);
CTASSERT(sizeof(void *__capability) == 32);
CTASSERT(sizeof(struct chericap) == 32);
CTASSERT(sizeof(struct cheri_object) == 64);
#endif

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
}
SYSINIT(cheri_cpu_startup, SI_SUB_CPU, SI_ORDER_FIRST, cheri_cpu_startup,
    NULL);

/*
 * Build a new capabilty derived from $kdc with the contents of the passed
 * flattened representation.  Only unsealed capabilities are supported;
 * capabilities must be separately sealed if required.
 *
 * XXXRW: It's not yet clear how important ordering is here -- try to do the
 * privilege downgrade in a way that will work when doing an "in place"
 * downgrade, with permissions last.
 *
 * XXXRW: In the new world order of CSetBounds, it's not clear that taking
 * explicit base/length/offset arguments is quite the right thing.
 */
void
cheri_capability_set(void * __capability *cp, uint32_t perms, vaddr_t basep,
    size_t length, off_t off)
{
	/* 'basep' is relative to $kdc. */
	*cp = cheri_setoffset(cheri_andperm(cheri_csetbounds(
	    cheri_incoffset(cheri_getkdc(), basep), length), perms),
	    off);

	/*
	 * NB: With imprecise bounds, we want to assert that the results will
	 * be 'as requested' -- i.e., that the kernel always request bounds
	 * that can be represented precisly.
	 *
	 * XXXRW: Given these assupmtions, we actually don't need to do the
	 * '+= off' above.
	 */
#ifdef INVARIANTS
	KASSERT(cheri_gettag(*cp) != 0, ("%s: capability untagged", __func__));
	KASSERT(cheri_getperm(*cp) == (register_t)perms,
	    ("%s: permissions 0x%lx rather than 0x%x", __func__,
	    (unsigned long)cheri_getperm(*cp), perms));
	KASSERT(cheri_getbase(*cp) == (register_t)basep,
	    ("%s: base %p rather than %lx", __func__,
	     (void *)cheri_getbase(*cp), basep));
	KASSERT(cheri_getlen(*cp) == (register_t)length,
	    ("%s: length 0x%lx rather than %p", __func__,
	    (unsigned long)cheri_getlen(*cp), (void *)length));
	KASSERT(cheri_getoffset(*cp) == (register_t)off,
	    ("%s: offset %p rather than %p", __func__,
	    (void *)cheri_getoffset(*cp), (void *)off));
#endif
}

/*
 * Functions to store a common set of capability values to in-memory
 * capabilities used in various aspects of user contexts.
 */
#ifdef _UNUSED
static void
cheri_capability_set_kern(void * __capability *cp)
{

	cheri_capability_set(cp, CHERI_CAP_KERN_PERMS, CHERI_CAP_KERN_BASE,
	    CHERI_CAP_KERN_LENGTH, CHERI_CAP_KERN_OFFSET);
}
#endif

void
cheri_capability_set_user_sigcode(void * __capability *cp,
    const struct sysentvec *se)
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

	cheri_capability_set(cp, CHERI_CAP_USER_CODE_PERMS, base,
	    szsigcode, 0);
}

void
cheri_capability_set_user_sealcap(void * __capability *cp)
{

	cheri_capability_set(cp, CHERI_SEALCAP_USERSPACE_PERMS,
	    CHERI_SEALCAP_USERSPACE_BASE, CHERI_SEALCAP_USERSPACE_LENGTH,
	    CHERI_SEALCAP_USERSPACE_OFFSET);
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

static int
cosetup(struct thread *td)
{
	vm_map_t map;
	vm_map_entry_t entry;
	vaddr_t addr;
	boolean_t found;
	int error;

	KASSERT(td->td_switcher_data == 0, ("%s: already initialized\n", __func__));

	/*
	 * XXX: Race between this and setting the owner.
	 */
	error = kern_mmap(td, 0, 0, PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE, MAP_ANON, -1, 0);
	if (error != 0) {
		printf("%s: kern_mmap() failed with error %d\n", __func__, error);
		return (error);
	}

	addr = td->td_retval[0];
	td->td_switcher_data = addr;
	td->td_retval[0] = 0;

	map = &td->td_proc->p_vmspace->vm_map;
	vm_map_lock(map);
	found = vm_map_lookup_entry(map, addr, &entry);
	KASSERT(found == TRUE, ("%s: vm_map_lookup_entry returned false\n", __func__));

	entry->owner = 0;
	vm_map_unlock(map);

	return (0);
}

int
sys_cosetup(struct thread *td, struct cosetup_args *uap)
{
	void * __capability codecap;
	void * __capability datacap;
	vaddr_t addr;
	int error;

	if (td->td_switcher_data == 0) {
		error = cosetup(td);
		if (error != 0)
			return (error);
	}

	addr = td->td_switcher_data;

	switch (uap->what) {
	case COSETUP_COCALL:
		cheri_capability_set(&codecap, CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cocall_base,
		    td->td_proc->p_sysent->sv_cocall_len, 0);
		codecap = cheri_seal(codecap, curproc->p_md.md_cheri_sealcap);
		error = copyoutcap(&codecap, uap->code, sizeof(codecap));
		if (error != 0)
			return (error);

		cheri_capability_set(&datacap, CHERI_CAP_USER_DATA_PERMS, addr, PAGE_SIZE, 0);
		datacap = cheri_seal(datacap, curproc->p_md.md_cheri_sealcap);
		error = copyoutcap(&datacap, uap->data, sizeof(datacap));
		return (0);

	case COSETUP_COACCEPT:
		cheri_capability_set(&codecap, CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_coaccept_base,
		    td->td_proc->p_sysent->sv_coaccept_len, 0);
		codecap = cheri_seal(codecap, curproc->p_md.md_cheri_sealcap);
		error = copyoutcap(&codecap, uap->code, sizeof(codecap));
		if (error != 0)
			return (error);

		cheri_capability_set(&datacap, CHERI_CAP_USER_DATA_PERMS, addr, PAGE_SIZE, 0);
		datacap = cheri_seal(datacap, curproc->p_md.md_cheri_sealcap);
		error = copyoutcap(&datacap, uap->data, sizeof(datacap));
		return (0);

	default:
		return (EINVAL);
	}
}

int
sys_coregister(struct thread *td, struct coregister_args *uap)
{
	struct vmspace *vmspace;
	struct coname *con;
	char name[PATH_MAX];
	void * __capability cap;
	vaddr_t addr;
	int error;

	vmspace = td->td_proc->p_vmspace;

	error = copyinstr(uap->name, name, sizeof(name), NULL);
	if (error != 0)
		return (error);

	if (strlen(name) == 0)
		return (EINVAL);

	if (strlen(name) >= PATH_MAX)
		return (ENAMETOOLONG);

	if (td->td_switcher_data == 0) {
		error = cosetup(td);
		if (error != 0)
			return (error);
	}

	addr = td->td_switcher_data;

	vm_map_lock(&vmspace->vm_map);
	LIST_FOREACH(con, &vmspace->vm_conames, c_next) {
		if (strcmp(name, con->c_name) == 0) {
			vm_map_unlock(&vmspace->vm_map);
			return (EEXIST);
		}
	}

	cheri_capability_set(&cap, CHERI_CAP_USER_DATA_PERMS, addr, PAGE_SIZE, 1024 /* XXX */);
	cap = cheri_seal(cap, curproc->p_md.md_cheri_sealcap);

	if (uap->cap != NULL) {
		error = copyoutcap(&cap, uap->cap, sizeof(cap));
		if (error != 0) {
			vm_map_unlock(&vmspace->vm_map);
			return (error);
		}
	}

	con = malloc(sizeof(struct coname), M_TEMP, M_WAITOK);
	con->c_name = strdup(name, M_TEMP);
	con->c_value = cap;
	LIST_INSERT_HEAD(&vmspace->vm_conames, con, c_next);
	vm_map_unlock(&vmspace->vm_map);

	return (0);
}

int
sys_colookup(struct thread *td, struct colookup_args *uap)
{
	struct vmspace *vmspace;
	const struct coname *con;
	char name[PATH_MAX];
	int error;

	vmspace = td->td_proc->p_vmspace;

	error = copyinstr(uap->name, name, sizeof(name), NULL);
	if (error != 0)
		return (error);

	vm_map_lock(&vmspace->vm_map);
	LIST_FOREACH(con, &vmspace->vm_conames, c_next) {
		if (strcmp(name, con->c_name) == 0)
			break;
	}

	if (con == NULL) {
		vm_map_unlock(&vmspace->vm_map);
		return (ESRCH);
	}

	error = copyoutcap(&con->c_value, uap->cap, sizeof(con->c_value));
	vm_map_unlock(&vmspace->vm_map);
	return (error);
}
