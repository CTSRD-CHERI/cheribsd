/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2006 Wojciech A. Koszek <wkoszek@FreeBSD.org>
 * Copyright (c) 2012-2014 Robert N. M. Watson
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
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"
#include "opt_platform.h"

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/imgact.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/cons.h>
#include <sys/exec.h>
#include <sys/endian.h>
#include <sys/linker.h>
#include <sys/ucontext.h>
#include <sys/proc.h>
#include <sys/kdb.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/signalvar.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/user.h>

#ifdef FDT
#include <contrib/libfdt/libfdt.h>
#include <contrib/libfdt/fdt.h>
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_subr.h>
#endif

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>
#include <vm/vm_dumpset.h>

#include <machine/bootinfo.h>
#include <machine/clock.h>
#include <machine/cpu.h>
#include <machine/cpuregs.h>
#include <machine/hwfunc.h>
#include <machine/md_var.h>
#include <machine/metadata.h>
#include <machine/pmap.h>
#include <machine/trap.h>

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cheric.h>
#endif

#define	FDT_SOURCE_NONE		0
#define	FDT_SOURCE_LOADER	1
#define	FDT_SOURCE_ROM		2
#define	FDT_SOURCE_STATIC	3

#if defined(FDT_DTB_STATIC_ONLY) && !defined(FDT_DTB_STATIC)
#define FDT_DTB_STATIC
#endif

extern int	*edata;
extern int	*end;

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * XXX-AM: Create a pointer for the platform-specific data structures.
 * Currently we do not set bounds of these as it is hard to determine
 * correct bounds. Only load permission are handed out.
 */
static void *
beri_platform_ptr(vm_offset_t vaddr)
{
	if (vaddr == 0)
		return (NULL);

	void *cap = cheri_setaddress(kernel_root_cap, vaddr);
	cap = cheri_andperm(cap, CHERI_PERM_LOAD);

	return (cap);
}

static void *
beri_platform_ptrbounds(vm_offset_t vaddr, size_t len)
{
	if (vaddr == 0)
		return (NULL);
	return (cheri_setbounds(beri_platform_ptr(vaddr), len));
}

static void
platform_clear_bss(void *kroot)
{
	/*
	 * We need to hand-craft a capability for edata because it is defined
	 * by the linker script and have no size info.
	 */
	void *edata_start;
	ptrdiff_t edata_siz = (ptraddr_t)&end - (ptraddr_t)&edata;

	edata_start = cheri_ptrperm(
		cheri_setaddress(kroot, (ptraddr_t)&edata),
		edata_siz, CHERI_PERM_STORE);
	memset(edata_start, 0, edata_siz);
}
#else /* __CHERI_PURE_CAPABILITY__ */
static void *
beri_platform_ptr(vm_offset_t vaddr)
{
	return ((void *)vaddr);
}

static void *
beri_platform_ptrbounds(vm_offset_t vaddr, size_t len)
{
	return ((void *)vaddr);
}

static void
platform_clear_bss()
{
	vm_offset_t kernend = (vm_offset_t)&end;

	memset(&edata, 0, kernend - (vm_offset_t)(&edata));
}
#endif /* __CHERI_PURE_CAPABILITY__ */

void
platform_cpu_init()
{
	/* Nothing special */
}

static void
mips_init(void)
{
	int i;
#ifdef FDT
	struct mem_region mr[FDT_MEM_REGIONS];
	uint64_t val;
	int mr_cnt;
	int j;
#endif

	for (i = 0; i < 10; i++) {
		phys_avail[i] = 0;
	}

	/* phys_avail regions are in bytes */
	phys_avail[0] = MIPS_KSEG0_TO_PHYS(kernel_kseg0_end);
	phys_avail[1] = ctob(realmem);

	dump_avail[0] = phys_avail[0];
	dump_avail[1] = phys_avail[1];

	physmem = realmem;

#ifdef FDT
	if (fdt_get_mem_regions(mr, &mr_cnt, &val) == 0) {
		physmem = btoc(val);

		KASSERT((phys_avail[0] >= mr[0].mr_start) && \
			(phys_avail[0] < (mr[0].mr_start + mr[0].mr_size)),
			("First region is not within FDT memory range"));

		/* Limit size of the first region */
		phys_avail[1] = (mr[0].mr_start + MIN(mr[0].mr_size, ctob(realmem)));
		dump_avail[1] = phys_avail[1];

		/* Add the rest of regions */
		for (i = 1, j = 2; i < mr_cnt; i++, j+=2) {
			phys_avail[j] = mr[i].mr_start;
			phys_avail[j+1] = (mr[i].mr_start + mr[i].mr_size);
			dump_avail[j] = phys_avail[j];
			dump_avail[j+1] = phys_avail[j+1];
		}
	}
#endif

	init_param1();
	init_param2(physmem);
	mips_cpu_init();
	pmap_bootstrap();
	mips_proc0_init();
	mutex_init();
	kdb_init();
#ifdef KDB
	if (boothowto & RB_KDB)
		kdb_enter(KDB_WHY_BOOTFLAGS, "Boot flags requested debugger");
#endif
}

/*
 * Perform a board-level soft-reset.
 */
void
platform_reset(void)
{

	/* XXX SMP will likely require us to do more. */
	__asm__ __volatile__(
		"mfc0 $k0, $12\n\t"
		"li $k1, 0x00100000\n\t"
		"or $k0, $k0, $k1\n\t"
		"mtc0 $k0, $12\n");
	for( ; ; )
		__asm__ __volatile("wait");
}

void
platform_start(__register_t a0, __register_t a1,  __register_t a2,
    __register_t a3)
{
	struct bootinfo *bootinfop;
	uint64_t platform_counter_freq;
	int argc = a0;
	ptraddr_t *argv;
	ptraddr_t *envp;
	long memsize;
	char *boot_env;
#ifdef FDT
	char *dtbp = NULL;
	void *kmdp;
	int dtb_needs_swap = 0; /* error */
	size_t dtb_size = 0;
#ifndef FDT_DTB_STATIC_ONLY
	struct fdt_header *dtb_rom, *dtb;
	uint32_t *swapptr;
#endif
	int fdt_source = FDT_SOURCE_NONE;
#endif
	int i;

	argv = beri_platform_ptr(a1);
	envp = beri_platform_ptr(a2);
	/* clear the BSS and SBSS segments */
#ifdef __CHERI_PURE_CAPABILITY__
	platform_clear_bss(kernel_data_cap);
#else
	platform_clear_bss();
#endif

	mips_postboot_fixup();

	mips_pcpu0_init();

	/*
	 * Over time, we've changed out boot-time binary interface for the
	 * kernel.  Miniboot simply provides a 'memsize' in a3, whereas the
	 * FreeBSD boot loader provides a 'bootinfo *' in a3.  While slightly
	 * grody, we support both here by detecting 'pointer-like' values in
	 * a3 and assuming physical memory can never be that big.
	 *
	 * XXXRW: Pull more values than memsize out of bootinfop -- e.g.,
	 * module information.
	 */
	if (a3 >= 0x9800000000000000ULL) {
		bootinfop = beri_platform_ptrbounds(
		    a3, sizeof(struct bootinfo));
		preload_metadata = beri_platform_ptr(bootinfop->bi_modulep);
		memsize = bootinfop->bi_memsize;
	} else {
		bootinfop = NULL;
		memsize = a3;
#ifdef CPU_CHERI
		/* Ensure that we don't write to the tag memory */
		if (memsize > 2ul * 1024 * 1024 * 1024)
			panic("invalid memsize 0x%lx", memsize);
		/*
		 * The memory size reported by miniboot is wrong for CHERI:
		 * The tag memory always starts at 3EFFC000, so we mustn't
		 * write to any addresses higher than 3EFFC000.
		 */
		memsize = MIN(memsize, 0x3EFFC000);
#endif
	}

	kmdp = preload_search_by_type("elf kernel");
	/*
	 * Configure more boot-time parameters passed in by loader.
	 */
	boothowto = MD_FETCH(kmdp, MODINFOMD_HOWTO, int);
	boot_env = beri_platform_ptr(
	    MD_FETCH(kmdp, MODINFOMD_ENVP, vm_offset_t));
	init_static_kenv(boot_env, 0);


#ifdef FDT
#ifndef FDT_DTB_STATIC_ONLY
	/*
	 * Find the dtb passed in by the boot loader (currently fictional).
	 *
	 * Prefer a dtb provided as a module to one from bootinfo as we may
	 * have loaded an alternative one or created a modified version.
	 */
	dtbp = beri_platform_ptr(MD_FETCH(kmdp, MODINFOMD_DTBP, vm_offset_t));
	if (dtbp == NULL &&
	    bootinfop != NULL && bootinfop->bi_dtb != (bi_ptr_t)NULL) {
		dtbp = beri_platform_ptr(bootinfop->bi_dtb);
		fdt_source = FDT_SOURCE_LOADER;
	}

	/* Try to find an FDT directly in the hardware */
	if (dtbp == NULL) {
		dtb_rom = beri_platform_ptr(0x900000007f010000);
		if (dtb_rom->magic == FDT_MAGIC) {
			dtb_needs_swap = 0;
			dtb_size = dtb_rom->totalsize;
		} else if (dtb_rom->magic == bswap32(FDT_MAGIC)) {
			dtb_needs_swap = 1;
			dtb_size = bswap32(dtb_rom->totalsize);
		}
		if (dtb_size != 0) {
			/* Steal a bit of memory... */
			dtb = beri_platform_ptr(kernel_kseg0_end);
			/* Round alignment from linker script. */
			kernel_kseg0_end += roundup2(dtb_size, 64 / 8);
			memcpy(dtb, dtb_rom, dtb_size);
			if (dtb_needs_swap)
				for (swapptr = (uint32_t *)dtb;
				    swapptr < (uint32_t *)dtb + (dtb_size/sizeof(*dtb));
				    swapptr++)
					*swapptr = bswap32(*swapptr);
			dtbp = (char *)dtb;
			fdt_source = FDT_SOURCE_ROM;
		}
	}
#endif /* !FDT_DTB_STATIC_ONLY */

#if defined(FDT_DTB_STATIC)
	/*
	 * In case the device tree blob was not retrieved (from metadata) try
	 * to use the statically embedded one.
	 */
	if (dtbp == NULL) {
		dtbp = fdt_static_dtb;
		fdt_source = FDT_SOURCE_STATIC;
	}
#endif

	if (OF_install(OFW_FDT, 0) == FALSE)
		panic("OF_install failed.");
	if (OF_init((void *)dtbp) != 0)
		panic("OF_init failed.");

	/*
	 * Get bootargs from FDT if specified.
	 */
	ofw_parse_bootargs();
#endif

	/*
	 * XXXRW: We have no way to compare wallclock time to cycle rate on
	 * BERI, so for now assume we run at the MALTA default (100MHz).
	 */
	platform_counter_freq = MIPS_DEFAULT_HZ;
	mips_timer_early_init(platform_counter_freq);

	cninit();
	printf("entry: platform_start()\n");

#ifdef FDT
	if (dtbp != NULL) {
		printf("Using FDT at %p from ", (void *)dtbp);
		switch (fdt_source) {
		case FDT_SOURCE_LOADER:
			printf("loader");
			break;
		case FDT_SOURCE_ROM:
			printf("ROM");
			break;
		case FDT_SOURCE_STATIC:
			printf("kernel");
			break;
		default:
			printf("unknown source %d", fdt_source);
			break;
		}
		printf("\n");
	}
	if (dtb_size != 0 && dtb_needs_swap)
		printf("FDT was byteswapped\n");
#endif

	bootverbose = 1;
	if (bootverbose) {
		printf("cmd line: ");
		for (i = 0; i < argc; i++) {
			char *argv_value = beri_platform_ptr(argv[i]);
			printf("%s ", argv_value);
		}
		printf("\n");

		printf("envp:\n");
		for (i = 0; envp[i]; i += 2) {
			char *envp_name = beri_platform_ptr(envp[i]);
			char *envp_value = beri_platform_ptr(envp[i+1]);
			printf("\t%s = %s\n", envp_name, envp_value);
		}

		if (bootinfop != NULL) {
			printf("bootinfo found at %p, "
			    "bootinfop->bi_memsize=0x%lx\n", bootinfop,
			    (long)bootinfop->bi_memsize);
			hexdump(bootinfop, sizeof(*bootinfop), "Bootinfo:", 0);
		}

		printf("memsize = %p\n", (void *)(uintptr_t)memsize);
	}

	realmem = btoc(memsize);
	mips_init();

	mips_timer_init_params(platform_counter_freq, 0);
}
// CHERI CHANGES START
// {
//   "updated": 20200528,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "pointer_as_integer"
//   ]
// }
// CHERI CHANGES END
