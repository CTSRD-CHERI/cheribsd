/*-
 * Copyright (c) 2012 Konstantin Belousov <kib@FreeBSD.org>
 * Copyright (c) 2016, 2017 The FreeBSD Foundation
 * All rights reserved.
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
#include "namespace.h"
#include <sys/capsicum.h>
#include <sys/elf.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/vdso.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "un-namespace.h"
#include <machine/atomic.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <dev/acpica/acpi_hpet.h>
#ifdef WANT_HYPERV
#include <dev/hyperv/hyperv.h>
#endif
#include "libc_private.h"

static enum LMB {
	LMB_UNKNOWN,
	LMB_NONE,
	LMB_MFENCE,
	LMB_LFENCE
} lfence_works = LMB_UNKNOWN;

static void
cpuidp(u_int leaf, u_int p[4])
{

	__asm __volatile(
#if defined(__i386__)
	    "	pushl	%%ebx\n"
#endif
	    "	cpuid\n"
#if defined(__i386__)
	    "	movl	%%ebx,%1\n"
	    "	popl	%%ebx"
#endif
	    : "=a" (p[0]),
#if defined(__i386__)
	    "=r" (p[1]),
#elif defined(__amd64__)
	    "=b" (p[1]),
#else
#error "Arch"
#endif
	    "=c" (p[2]), "=d" (p[3])
	    :  "0" (leaf));
}

static enum LMB
select_lmb(void)
{
	u_int p[4];
	static const char intel_id[] = "GenuntelineI";

	cpuidp(0, p);
	return (memcmp(p + 1, intel_id, sizeof(intel_id) - 1) == 0 ?
	    LMB_LFENCE : LMB_MFENCE);
}

static void
init_fence(void)
{
#if defined(__i386__)
	u_int cpuid_supported, p[4];

	lfence_works = LMB_NONE;
	__asm __volatile(
	    "	pushfl\n"
	    "	popl	%%eax\n"
	    "	movl    %%eax,%%ecx\n"
	    "	xorl    $0x200000,%%eax\n"
	    "	pushl	%%eax\n"
	    "	popfl\n"
	    "	pushfl\n"
	    "	popl    %%eax\n"
	    "	xorl    %%eax,%%ecx\n"
	    "	je	1f\n"
	    "	movl	$1,%0\n"
	    "	jmp	2f\n"
	    "1:	movl	$0,%0\n"
	    "2:\n"
	    : "=r" (cpuid_supported) : : "eax", "ecx", "cc");
	if (cpuid_supported) {
		cpuidp(0x1, p);
		if ((p[3] & CPUID_SSE2) != 0)
			lfence_works = select_lmb();
	}
#elif defined(__amd64__)
	lfence_works = select_lmb();
#else
#error "Arch"
#endif
}

static void
rdtsc_mb(void)
{

again:
	if (__predict_true(lfence_works == LMB_LFENCE)) {
		lfence();
		return;
	} else if (lfence_works == LMB_MFENCE) {
		mfence();
		return;
	} else if (lfence_works == LMB_NONE) {
		return;
	}
	init_fence();
	goto again;
}

static u_int
__vdso_gettc_rdtsc_low(const struct vdso_timehands *th)
{
	u_int rv;

	rdtsc_mb();
	__asm __volatile("rdtsc; shrd %%cl, %%edx, %0"
	    : "=a" (rv) : "c" (th->th_x86_shift) : "edx");
	return (rv);
}

static u_int
__vdso_rdtsc32(void)
{

	rdtsc_mb();
	return (rdtsc32());
}

#define	HPET_DEV_MAP_MAX	10
static volatile char *hpet_dev_map[HPET_DEV_MAP_MAX];

static void
__vdso_init_hpet(uint32_t u)
{
	static const char devprefix[] = "/dev/hpet";
	char devname[64], *c, *c1, t;
	volatile char *new_map, *old_map;
	unsigned int mode;
	uint32_t u1;
	int fd;

	c1 = c = stpcpy(devname, devprefix);
	u1 = u;
	do {
		*c++ = u1 % 10 + '0';
		u1 /= 10;
	} while (u1 != 0);
	*c = '\0';
	for (c--; c1 != c; c1++, c--) {
		t = *c1;
		*c1 = *c;
		*c = t;
	}

	old_map = hpet_dev_map[u];
	if (old_map != NULL)
		return;

	/*
	 * Explicitely check for the capability mode to avoid
	 * triggering trap_enocap on the device open by absolute path.
	 */
	if ((cap_getmode(&mode) == 0 && mode != 0) ||
	    (fd = _open(devname, O_RDONLY)) == -1) {
		/* Prevent the caller from re-entering. */
		atomic_cmpset_rel_ptr((volatile uintptr_t *)&hpet_dev_map[u],
		    (uintptr_t)old_map, (uintptr_t)MAP_FAILED);
		return;
	}

	new_map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	_close(fd);
	if (atomic_cmpset_rel_ptr((volatile uintptr_t *)&hpet_dev_map[u],
	    (uintptr_t)old_map, (uintptr_t)new_map) == 0 &&
	    new_map != MAP_FAILED)
		munmap((void *)new_map, PAGE_SIZE);
}

#ifdef WANT_HYPERV

#define HYPERV_REFTSC_DEVPATH	"/dev/" HYPERV_REFTSC_DEVNAME

/*
 * NOTE:
 * We use 'NULL' for this variable to indicate that initialization
 * is required.  And if this variable is 'MAP_FAILED', then Hyper-V
 * reference TSC can not be used, e.g. in misconfigured jail.
 */
static struct hyperv_reftsc *hyperv_ref_tsc;

static void
__vdso_init_hyperv_tsc(void)
{
	int fd;
	unsigned int mode;

	if (cap_getmode(&mode) == 0 && mode != 0)
		goto fail;

	fd = _open(HYPERV_REFTSC_DEVPATH, O_RDONLY);
	if (fd < 0)
		goto fail;
	hyperv_ref_tsc = mmap(NULL, sizeof(*hyperv_ref_tsc), PROT_READ,
	    MAP_SHARED, fd, 0);
	_close(fd);

	return;
fail:
	/* Prevent the caller from re-entering. */
	hyperv_ref_tsc = MAP_FAILED;
}

static int
__vdso_hyperv_tsc(struct hyperv_reftsc *tsc_ref, u_int *tc)
{
	uint64_t disc, ret, tsc, scale;
	uint32_t seq;
	int64_t ofs;

	while ((seq = atomic_load_acq_int(&tsc_ref->tsc_seq)) != 0) {
		scale = tsc_ref->tsc_scale;
		ofs = tsc_ref->tsc_ofs;

		rdtsc_mb();
		tsc = rdtsc();

		/* ret = ((tsc * scale) >> 64) + ofs */
		__asm__ __volatile__ ("mulq %3" :
		    "=d" (ret), "=a" (disc) :
		    "a" (tsc), "r" (scale));
		ret += ofs;

		atomic_thread_fence_acq();
		if (tsc_ref->tsc_seq == seq) {
			*tc = ret;
			return (0);
		}

		/* Sequence changed; re-sync. */
	}
	return (ENOSYS);
}

#endif	/* WANT_HYPERV */

#pragma weak __vdso_gettc
int
__vdso_gettc(const struct vdso_timehands *th, u_int *tc)
{
	volatile char *map;
	uint32_t idx;

	switch (th->th_algo) {
	case VDSO_TH_ALGO_X86_TSC:
		*tc = th->th_x86_shift > 0 ? __vdso_gettc_rdtsc_low(th) :
		    __vdso_rdtsc32();
		return (0);
	case VDSO_TH_ALGO_X86_HPET:
		idx = th->th_x86_hpet_idx;
		if (idx >= HPET_DEV_MAP_MAX)
			return (ENOSYS);
		map = (volatile char *)atomic_load_acq_ptr(
		    (volatile uintptr_t *)&hpet_dev_map[idx]);
		if (map == NULL) {
			__vdso_init_hpet(idx);
			map = (volatile char *)atomic_load_acq_ptr(
			    (volatile uintptr_t *)&hpet_dev_map[idx]);
		}
		if (map == MAP_FAILED)
			return (ENOSYS);
		*tc = *(volatile uint32_t *)(map + HPET_MAIN_COUNTER);
		return (0);
#ifdef WANT_HYPERV
	case VDSO_TH_ALGO_X86_HVTSC:
		if (hyperv_ref_tsc == NULL)
			__vdso_init_hyperv_tsc();
		if (hyperv_ref_tsc == MAP_FAILED)
			return (ENOSYS);
		return (__vdso_hyperv_tsc(hyperv_ref_tsc, tc));
#endif
	default:
		return (ENOSYS);
	}
}

#pragma weak __vdso_gettimekeep
int
__vdso_gettimekeep(struct vdso_timekeep **tk)
{

	return (_elf_aux_info(AT_TIMEKEEP, tk, sizeof(*tk)));
}
