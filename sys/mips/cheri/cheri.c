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
/* 28 capability registers + capcause + padding. */
CTASSERT(sizeof(struct cheri_frame) == (29 * CHERICAP_SIZE));

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

static void * __capability userspace_cap;
static void * __capability user_sealcap;

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
	 * Create a capability covering all of userspace from which to
	 * derive new capabilities in execve(), etc.
	 *
	 * XXX-BD: A hardline, no-exceptions W^X implementation would split
	 * the userspace capability here.
	 *
	 * XXX-BD: This is actually an ABI property and should probably
	 * per sysent.
	 *
	 * XXX-BD: this should happen earlier in startup.
	 */
	_Static_assert(CHERI_CAP_USER_DATA_BASE == CHERI_CAP_USER_CODE_BASE,
	    "Code and data bases differ");
	_Static_assert(CHERI_CAP_USER_DATA_LENGTH == CHERI_CAP_USER_CODE_LENGTH,
	    "Code and data lengths differ");
	_Static_assert(CHERI_CAP_USER_DATA_OFFSET == 0,
	    "Data offset is non-zero");
	_Static_assert(CHERI_CAP_USER_CODE_OFFSET == 0,
	    "Code offset is non-zero");
	userspace_cap = cheri_andperm(cheri_csetbounds(
	    cheri_setoffset(cheri_getkdc(), CHERI_CAP_USER_DATA_BASE),
	    CHERI_CAP_USER_DATA_LENGTH),
	    CHERI_CAP_USER_DATA_PERMS | CHERI_CAP_USER_CODE_PERMS);

	/*
	 * Create a capability for userspace to seal capabilities with.
	 */
	cheri_capability_set(&user_sealcap, CHERI_SEALCAP_USERSPACE_PERMS,
	    CHERI_SEALCAP_USERSPACE_BASE, CHERI_SEALCAP_USERSPACE_LENGTH,
	    CHERI_SEALCAP_USERSPACE_OFFSET);

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
cheri_capability_build_user_code(uint32_t perms, vaddr_t basep, size_t length,
    off_t off)
{

	KASSERT((perms & ~CHERI_CAP_USER_CODE_PERMS) == 0,
	    ("perms %x has permission not in CHERI_CAP_USER_CODE_PERMS %x",
	    perms, CHERI_CAP_USER_CODE_PERMS));

	return (cheri_capability_build_user_rwx(
	    perms & CHERI_CAP_USER_CODE_PERMS, basep, length, off));
}

/*
 * Build a new userspace capability derived from userspace_cap.
 * The resulting capability may include read and write permissions, but
 * not execute.
 */
void * __capability
cheri_capability_build_user_data(uint32_t perms, vaddr_t basep, size_t length,
    off_t off)
{

	KASSERT((perms & ~CHERI_CAP_USER_DATA_PERMS) == 0,
	    ("perms %x has permission not in CHERI_CAP_USER_DATA_PERMS %x",
	    perms, CHERI_CAP_USER_DATA_PERMS));

	return (cheri_capability_build_user_rwx(
	    perms & CHERI_CAP_USER_DATA_PERMS, basep, length, off));
}

/*
 * Build a new userspace capability derived from userspace_cap.
 * The resulting capability may include read, write, and execute permissions.
 *
 * This function violates W^X and its use is discouraged and the reason for
 * use should be documented in a comment when it is used.
 */
void * __capability
cheri_capability_build_user_rwx(uint32_t perms, vaddr_t basep, size_t length,
    off_t off)
{
	void * __capability tmpcap;

	tmpcap = cheri_setoffset(cheri_andperm(cheri_csetbounds(
	    cheri_setoffset(userspace_cap, basep), length), perms), off);

	KASSERT(cheri_getlen(tmpcap) == length,
	    ("Constructed capability has wrong length %zu != %zu",
	    cheri_getlen(tmpcap), length));

	return (tmpcap);
}

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
