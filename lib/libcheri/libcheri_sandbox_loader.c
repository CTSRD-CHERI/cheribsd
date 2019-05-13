/*-
 * Copyright (c) 2012-2017 Robert N. M. Watson
 * Copyright (c) 2015 SRI International
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libcheri_ccall.h"
#include "libcheri_class.h"
#include "libcheri_invoke.h"
#include "libcheri_system.h"
#include "libcheri_type.h"
#include "libcheri_sandbox.h"
#include "libcheri_sandbox_elf.h"
#include "libcheri_sandbox_internal.h"
#include "libcheri_sandbox_metadata.h"
#include "libcheri_sandbox_methods.h"
#include "libcheri_sandboxasm.h"
#include "libcheri_private.h"

#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */

#define	GUARD_PAGE_SIZE	0x1000
#define	METADATA_SIZE	0x1000

int
sandbox_class_load(struct sandbox_class *sbcp)
{
#ifdef SPLIT_CODE_DATA
	void * __capability codecap;
#endif
	int saved_errno;

	/*
	 * Set up the code capability for a new sandbox class.  Very similar
	 * to object setup (i.e., guard pages for NULL, etc).
	 *
	 * Eventually, we will want to do something a bit different here -- in
	 * particular, set up the code and data capabilities quite differently.
	 */

#ifdef SPLIT_CODE_DATA
	/*
	 * Ensure that we aren't going to map over NULL, guard pages, or
	 * metadata.  This check can probably be relaxed somewhat for
	 * the code capability, but for now it's right.
	 */
	if (sandbox_map_minoffset(sbcp->sbc_codemap) < SANDBOX_BINARY_BASE) {
		saved_errno = EINVAL;
		warnx("%s: sandbox wants to load below 0x%zx and 0x%zx",
		    __func__, (size_t)SANDBOX_BINARY_BASE,
		    sandbox_map_minoffset(sbcp->sbc_codemap));
		goto error;
	}

	sbcp->sbc_codelen = sandbox_map_maxoffset(sbcp->sbc_codemap);
	sbcp->sbc_codelen = roundup2(sbcp->sbc_codelen, PAGE_SIZE);
	base = sbcp->sbc_codemem = mmap(NULL, sbcp->sbc_codelen,
	    PROT_MAX(PROT_ALL)|PROT_NONE, MAP_ANON, -1, 0);
	if (sbcp->sbc_codemem == MAP_FAILED) {
		saved_errno = errno;
		warn("%s: mmap region", __func__);
		goto error;
	}
	if (sandbox_map_load(base, sbcp->sbc_codemap) == -1) {
		saved_errno = EINVAL;
		warnx("%s: sandbox_map_load(sbc_codemap)\n", __func__);
		goto error;
	}
#endif

	/*
	 * Parse the sandbox ELF binary for CCall methods provided and
	 * required.
	 */
	if (sandbox_parse_ccall_methods(sbcp->sbc_fd,
	     &sbcp->sbc_provided_classes, &sbcp->sbc_required_methods) < 0) {
		saved_errno = EINVAL;
		warnx("%s: sandbox_parse_ccall_methods() failed for %s",
		    __func__, sbcp->sbc_path);
		goto error;
	}

#ifdef SPLIT_CODE_DATA
	if (sandbox_map_protect(base, sbcp->sbc_codemap) == -1) {
		saved_errno = EINVAL;
		warnx("%s: sandbox_map_protect(sbc_codemap)\n", __func__);
		goto error;
	}

	/*
	 * Set bounds and mask permissions on code capabilities.
	 *
	 * XXXRW: In CheriABI, mmap(2) will return suitable bounds, so just
	 * mask permissions.  This is not well captured here.
	 *
	 * For both the MIPS ABI and CheriABI, we need to set suitable
	 * offsets.
	 *
	 * XXXRW: There are future questions to answer here about W^X and
	 * mmap(2) in CheriABI.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	codecap = cheri_andperm(sbcp->sbc_codemem,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_EXECUTE);
#else
	codecap = cheri_codeptrperm(sbcp->sbc_codemem, sbcp->sbc_codelen,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_EXECUTE);
#endif
	sbcp->sbc_classcap_rtld = cheri_setoffset(codecap,
	    SANDBOX_RTLD_VECTOR);

#ifdef __CHERI_PURE_CAPABILITY__
	codecap = cheri_andperm(sbcp->sbc_codemem,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_EXECUTE);
#else
	codecap = cheri_codeptrperm(sbcp->sbc_codemem, sbcp->sbc_codelen,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_EXECUTE);
#endif
	sbcp->sbc_classcap_invoke = cheri_setoffset(codecap,
	    SANDBOX_INVOKE_VECTOR);
#endif

	return (0);

error:
#ifdef SPLIT_CODE_DATA
	if (sbcp->sbc_codemem != NULL)
		munmap(sbcp->sbc_codemem, sbcp->sbc_codelen);
#endif
	errno = saved_errno;
	return (-1);
}

void
sandbox_class_unload(struct sandbox_class *sbcp)
{

#ifdef SPLIT_CODE_DATA
	munmap(sbcp->sbc_codemem, sbcp->sbc_codelen);
#else
	(void)sbcp;
#endif
}

int
sandbox_object_load(struct sandbox_class *sbcp, struct sandbox_object *sbop)
{
#ifndef SPLIT_CODE_DATA
	void * __capability codecap;
#endif
	void * __capability idc;
	struct sandbox_metadata *sbmp;
	size_t length;
	size_t heaplen;
	size_t max_prog_offset;
#if CHERICAP_SIZE == 16
	ssize_t heaplen_adj;
#endif
	int saved_errno;
	caddr_t base;

	/*
	 * Perform an initial reservation of space for the sandbox, but using
	 * anonymous memory that is neither readable nor writable.  This
	 * ensures there is space for all the various segments we will be
	 * installing later.
	 *
	 * The rough sandbox memory map is as follows:
	 *
	 * J + 0x1000 [internal (non-shareable) heap]
	 * J          [guard page]
	 *  +0x600      Reserved vector
	 *  +0x400      Reserved vector
	 *  +0x200      Object-capability invocation vector
	 *  +0x0        Run-time linker vector
	 * 0x8000     [memory mapped binary]
	 * 0x2000     [guard page]
	 * 0x1000     [read-only sandbox metadata page]
	 * 0x0000     [guard page]
	 *
	 * Address constants in sandbox.h must be synchronised with the layout
	 * implemented here.  Location and contents of sandbox metadata is
	 * part of the ABI.
	 */

	/*
	 * Ensure that we aren't going to map over NULL, guard pages, or
	 * metadata.
	 */
	if (sandbox_map_minoffset(sbcp->sbc_datamap) < SANDBOX_BINARY_BASE) {
		saved_errno = EINVAL;
		warnx("%s: sandbox wants to load below 0x%zx and 0x%zx",
		    __func__, (size_t)SANDBOX_BINARY_BASE,
		    sandbox_map_minoffset(sbcp->sbc_datamap));
		goto error;
	}

	/* 0x0000 and metadata covered by maxoffset */
	length = roundup2(sandbox_map_maxoffset(sbcp->sbc_datamap), PAGE_SIZE)
	    + GUARD_PAGE_SIZE;

	/*
	 * Compartment data mappings are often quite large, so we may need to
	 * adjust up the effective heap size on 128-bit CHERI to shift the top
	 * of the data segment closer to a suitable alignment boundary for a
	 * sealed capability.
	 */
	heaplen = roundup2(sbop->sbo_heaplen, PAGE_SIZE);
#if CHERICAP_SIZE == 16
	heaplen_adj = length + heaplen;		/* Requested length. */
	heaplen_adj = roundup2(heaplen_adj, (1ULL << CHERI_SEAL_ALIGN_SHIFT(heaplen_adj))); /* Aligned len. */
	heaplen_adj -= (length + heaplen);	/* Calculate adjustment. */
	heaplen += heaplen_adj;			/* Apply adjustment. */
#endif
	length += heaplen;
	sbop->sbo_datalen = length;
	base = sbop->sbo_datamem = mmap(NULL, length,
#ifdef SPLIT_CODE_DATA
	    PROT_MAX(PROT_READ|PROT_WRITE) | PROT_NONE,
#else
	    /* When mapping code+data together we have to use a RWX cap */
	    PROT_MAX(PROT_ALL) | PROT_NONE,
#endif
	    MAP_ANON | MAP_ALIGNED_CHERI_SEAL, -1, 0);
	if (sbop->sbo_datamem == MAP_FAILED) {
		saved_errno = errno;
		warn("%s: mmap region", __func__);
		goto error;
	}

	/*
	 * Assertions to make sure that we ended up with a well-aligned
	 * memory allocation as required for a precise set of bounds in the
	 * presence of compressed capabilities.
	 */
	assert(((vaddr_t)base & CHERI_SEAL_ALIGN_MASK(length)) == 0);

	/*
	 * Map and (eventually) link the program.
	 */
	if (sandbox_map_load(base, sbcp->sbc_datamap) == -1) {
		saved_errno = EINVAL;
		warnx("%s: sandbox_map_load(sbc_datamap)\n", __func__);
		goto error;
	}
	max_prog_offset = sandbox_map_maxoffset(sbcp->sbc_datamap);

	/*
	 * Skip guard page(s) to the base of the metadata structure.
	 */
	base += SANDBOX_METADATA_BASE;
	length -= SANDBOX_METADATA_BASE;

	/*
	 * Map metadata structure -- but can't fill it out until we have
	 * calculated all the other addresses involved.
	 */
	if ((sbmp = mmap(base, METADATA_SIZE, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_FIXED, -1, 0)) == MAP_FAILED) {
		saved_errno = errno;
		warn("%s: mmap metadata", __func__);
		goto error;
	}
	base += roundup2(METADATA_SIZE, PAGE_SIZE);
	length -= roundup2(METADATA_SIZE, PAGE_SIZE);

	/*
	 * Assert that we didn't bump into the sandbox entry address.  This
	 * address is hard to change as it is the address used in static
	 * linking for sandboxed code.
	 */
	assert((register_t)base - (register_t)sbop->sbo_datamem <
	    SANDBOX_BINARY_BASE);

	/*
	 * Skip already mapped binary.
	 */
	base = (caddr_t)sbop->sbo_datamem + roundup2(max_prog_offset, PAGE_SIZE);
	length = sbop->sbo_datalen - roundup2(max_prog_offset, PAGE_SIZE);

	/*
	 * Skip guard page.
	 */
	base += GUARD_PAGE_SIZE;
	length -= GUARD_PAGE_SIZE;

	/*
	 * Heap.
	 */
	sbop->sbo_heapbase = (register_t)base - (register_t)sbop->sbo_datamem;
	if (mmap(base, heaplen, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED,
	    -1, 0) == MAP_FAILED) {
		saved_errno = errno;
		warn("%s: mmap heap", __func__);
		goto error;
	}
	base += heaplen;
	length -= heaplen;

	/*
	 * There should not be too much, nor too little space remaining.  0
	 * is our Goldilocks number.
	 */
	assert(length == 0);

#ifndef SPLIT_CODE_DATA
	/*
	 * Set bounds and mask permissions on code capabilities.
	 *
	 * XXXRW: In CheriABI, mmap(2) will return suitable bounds, so just
	 * mask permissions.  This is not well captured here.
	 *
	 * For both the MIPS ABI and CheriABI, we need to set suitable
	 * offsets.
	 *
	 * XXXRW: There are future questions to answer here about W^X and
	 * mmap(2) in CheriABI.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	codecap = cheri_andperm(sbop->sbo_datamem,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |
	    CHERI_PERM_EXECUTE);
#else
	codecap = cheri_codeptrperm(sbop->sbo_datamem, sbop->sbo_datalen,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |
	    CHERI_PERM_EXECUTE);
#endif
	sbop->sbo_rtld_pcc = cheri_setoffset(codecap,
	    SANDBOX_RTLD_VECTOR);

#ifdef __CHERI_PURE_CAPABILITY__
	codecap = cheri_andperm(sbop->sbo_datamem,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |
	    CHERI_PERM_EXECUTE);
#else
	codecap = cheri_codeptrperm(sbop->sbo_datamem, sbop->sbo_datalen,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |
	    CHERI_PERM_EXECUTE);
#endif
	sbop->sbo_invoke_pcc = cheri_setoffset(codecap,
	    SANDBOX_INVOKE_VECTOR);
#endif /* !SPLIT_CODE_DATA */

	/*
	 * Now that addresses are known, write out metadata for in-sandbox
	 * use.  The stack was configured by the higher-level object code, so
	 * all we do is install the capability here.
	 */
	sbmp->sbm_heapbase = sbop->sbo_heapbase;
	sbmp->sbm_heaplen = heaplen;
	sbmp->sbm_vtable = sandbox_make_vtable(sbop->sbo_datamem, NULL,
	    sbcp->sbc_provided_classes);

	/*
	 * Construct data capability suitable for use with both run-time
	 * linking and invocation.
	 */
	idc = cheri_ptrperm(sbop->sbo_datamem, sbop->sbo_datalen,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |
	    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP);
	assert(cheri_getoffset(idc) == 0);
	assert(cheri_getlen(idc) == (size_t)sbop->sbo_datalen);

	/*
	 * Configure methods for object.
	 */
	if (sandbox_set_required_method_variables(idc, 0,
	    sbcp->sbc_required_methods) == -1) {
		saved_errno = EINVAL;
		warnx("%s: sandbox_set_ccaller_method_variables", __func__);
		goto error;
	}

	/*
	 * Set up the libcheri CCall trampoline environment.  Copy unsealed
	 * code capabilities for rtld and invocation from the sandbox class.
	 * As this is not a system class, set the vtable to NULL.  IDC is set
	 * to the sandbox object itself (as above).
	 *
	 * XXXRW: At this point, it would be good to check the properties of
	 * all of the generated capabilities: seal bit, base, length,
	 * permissions, etc, for what is expected, and fail if not.
	 *
	 * XXXBD: Ideally we would render the .CHERI_CCALLEE and
	 * .CHERI_CCALLER sections read-only at this point to avoid
	 * control-flow attacks.
	 *
	 * XXXRW: Where it the corresponding FINI?
	 */
	sbop->sbo_idc = idc;
#ifdef SPLIT_CODE_DATA
	sbop->sbo_rtld_pcc = sbcp->sbc_classcap_rtld;
	sbop->sbo_invoke_pcc = sbcp->sbc_classcap_invoke;
#endif
	sbop->sbo_vtable = NULL;
	sbop->sbo_ddc = idc;

#ifdef __CHERI_CAPABILITY_TLS__
	sbop->sbo_libcheri_tls = NULL;
#else
	sbop->sbo_libcheri_tls = cheri_getdefault();
#endif

	/*
	 * Construct sealed rtld and invocation capabilities for use with
	 * libcheri_invoke(), which will transition to the libcheri CCall
	 * trampoline.
	 */
	sbop->sbo_cheri_object_rtld =
	    libcheri_sandbox_make_sealed_rtld_object(
	    (__cheri_tocap struct sandbox_object * __capability)sbop);
	sbop->sbo_cheri_object_invoke =
	    libcheri_sandbox_make_sealed_invoke_object(
	    (__cheri_tocap struct sandbox_object * __capability)sbop);

	/*
	 * Set up a CHERI system object to service the sandbox's requests to
	 * the ambient environment.
	 *
	 * XXXRW: Should this occur earlier/later?
	 */
	if (libcheri_system_new(sbop, &sbop->sbo_sandbox_system_objectp) ==
	    -1) {
		saved_errno = errno;
		warnx("%s: unable to allocate system object", __func__);
		goto error;
	}

	/*
	 * Install a reference to the system object in the class.
	 */
	sbmp->sbm_system_object = sbop->sbo_cheri_object_system =
	    libcheri_sandbox_make_sealed_invoke_object(
	    (__cheri_tocap struct sandbox_object * __capability)
	    sbop->sbo_sandbox_system_objectp);

	/*
	 * Install CReturn capabilities in the class.
	 */
	sbmp->sbm_creturn_object = libcheri_make_sealed_return_object();

	/*
	 * Protect metadata now that we've written all values.
	 */
	if (mprotect(sbmp, METADATA_SIZE, PROT_READ) < 0) {
		saved_errno = errno;
		warn("%s: mprotect metadata", __func__);
		goto error;
	}
	return (0);

error:
	if (sbop->sbo_datamem != NULL)
		munmap(sbop->sbo_datamem, sbop->sbo_datalen);
	errno = saved_errno;
	return (-1);
}

int
sandbox_object_protect(struct sandbox_class *sbcp, struct sandbox_object *sbop)
{
	int saved_errno;

	if (sandbox_map_protect(sbop->sbo_datamem, sbcp->sbc_datamap) == -1) {
		saved_errno = EINVAL;
		warnx("%s: sandbox_map_protect(sbc_datamap)\n", __func__);
		errno = saved_errno;
		return (-1);
	}

	return (0);
}

/*
 * Reset the loader-managed address space to its start-time state.  Note that
 * this is not intended for use stand-alone, as sandbox_object_reset(), its
 * caller, is responsible for resetting the external stack(s).
 */
int
sandbox_object_reload(struct sandbox_object *sbop)
{
	int saved_errno;
	caddr_t base;
	size_t length;
	struct sandbox_class *sbcp;
	void * __capability datacap;

	assert(sbop != NULL);
	sbcp = sbop->sbo_sandbox_classp;
	assert(sbcp != NULL);

	if (sandbox_map_reload(sbop->sbo_datamem, sbcp->sbc_datamap) == -1) {
		saved_errno = EINVAL;
		warnx("%s:, sandbox_map_reset", __func__);
		goto error;
	}

	base = (caddr_t)sbop->sbo_datamem + sbop->sbo_heapbase;
	length = sbop->sbo_heaplen;
	if (mmap(base, length, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED,
	    -1, 0) == MAP_FAILED) {
		saved_errno = errno;
		warn("%s: mmap heap", __func__);
		goto error;
	}

	datacap = cheri_ptrperm(sbop->sbo_datamem, sbop->sbo_datalen,
	    CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP |
	    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
	    CHERI_PERM_STORE_LOCAL_CAP);
	if (sandbox_set_required_method_variables(datacap, 0,
	    sbcp->sbc_required_methods)
	    == -1) {
		saved_errno = EINVAL;
		warnx("%s: sandbox_set_ccaller_method_variables", __func__);
		goto error;
	}

	return (0);

error:
	if (sbop->sbo_datamem != NULL) {
		munmap(sbop->sbo_datamem, sbop->sbo_datalen);
		sbop->sbo_datamem = NULL;
	}
	errno = saved_errno;
	return (-1);
}

void
sandbox_object_unload(struct sandbox_object *sbop)
{
	struct sandbox_metadata *sbmp;

	sbmp = (void *)((char *)sbop->sbo_datamem +
	    SANDBOX_METADATA_BASE);
	free_c(sbmp->sbm_vtable);

	munmap(sbop->sbo_datamem, sbop->sbo_datalen);
}
