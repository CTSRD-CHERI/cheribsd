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

#ifndef _SANDBOX_INTERNAL_H_
#define	_SANDBOX_INTERNAL_H_

#include <sys/stat.h>

#include "cheri_class.h"

extern int	sb_verbose;

/*
 * Description of a 'sandbox class': an instance of code that may be sandboxed
 * and invoked, along with statistics/monitoring information, etc.
 *
 * NB: For now, support up to 'SANDBOX_CLASS_METHOD_COUNT' sets of method
 * statistics, which will be indexed by method number.  If the requested
 * method number isn't in range, use the catchall entry instead.
 */
#define	SANDBOX_CLASS_METHOD_COUNT	32
struct sandbox_class {
	char			*sbc_path;
	int			 sbc_fd;
	struct stat		 sbc_stat;
	size_t			 sbc_codelen;
	void			*sbc_codemem;
	struct sandbox_map	*sbc_codemap;
	struct sandbox_map	*sbc_datamap;

	/*
	 * The class's code capabilities, in various incarnations required for
	 * class creation.  These will be used for all objects in the class.
	 */
	__capability void	*sbc_classcap_rtld;	/* Ctor/dtor */
	__capability void	*sbc_classcap_invoke;	/* Object invoke */

	/*
	 * Class CCall methods.
	 */
	struct sandbox_provided_classes	*sbc_provided_classes;
	struct sandbox_required_methods	*sbc_required_methods;

	/*
	 * Class and invoke() method statistics.
	 */
	struct sandbox_class_stat	*sbc_sandbox_class_statp;
	struct sandbox_method_stat	*sbc_sandbox_method_nonamep;
	struct sandbox_method_stat	*sbc_sandbox_methods[
					    SANDBOX_CLASS_METHOD_COUNT];
};

/*-
 * Description of a 'sandbox object' or 'sandbox instance': an in-flight
 * combination of code and data.  Currently, due to compiler limitations, we
 * must conflate 'code', 'heap', and 'stack', but eventually would like to
 * allow one VM mapping of code to serve many object instances.  This would
 * also ease supporting multithreaded objects.
 *
 * TODO:
 * - Add atomically set flag and assertion to ensure single-threaded entry to
 *   the sandbox.
 */
struct
#if _MIPS_SZCAP == 128
__attribute__ ((aligned(4096)))
#endif
sandbox_object {
	/*
	 * IMPORTANT: These fields must be at the top of the sandbox_object,
	 * and in this specific order, as corresponding offsets to them are
	 * included in assembly domain-transition code in
	 * cheri_ccall_trampoline.S.
	 *
	 * sbo_idc         IDC to install for both rtld and invocation entry.
	 *		   The entry vector code will also use this
	 *		   capability, with offset set to zero, as the
	 *		   installed DDC.
	 *
	 * sbo_rtld_pcc    PCC to install for rtld operations.
	 *
	 * sbo_invoke_pcc  PCC to install on invocation.
	 *
	 * sbo_vtable      VTable pointer used for CHERI system classes;
	 *		   unused for loaded (confined) classes.
	 *
	 * sbo_ddc	   DDC to install on invocation.
	 *
	 * sbo_csp	   CSP to install on invocation.
	 *
	 * These capabilities are used by libcheri itself when accessing data
	 * from within the CCall trampoline, so that we don't have to assume
	 * that the sandbox_object pointer is DDC-relative:
	 *
	 * sbo_libcheri_tls	Access TLS relative to this register.
	 *
	 * XXXRW: It would be nice if the offsets to these fields were in
	 * shared headers, allowing compile-time asserts to be used to check
	 * binary compatibility has not been broken.
	 */
	__capability void	*sbo_idc;	/* Capability offset 0. */
	__capability void	*sbo_rtld_pcc;	/* Capability offset 1. */
	__capability void	*sbo_invoke_pcc;/* Capability offset 2. */
	__capability void	*sbo_vtable;	/* Capability offset 3. */
	__capability void	*sbo_ddc;	/* Capability offset 4. */
	__capability void	*sbo_libcheri_tls; /* Capability offset 5. */
	__capability void	*sbo_csp;	/* Capability offset 6. */
	union {
		int		 sbo_busy;	/* Capability offset 7. */
		__capability void *_sbo_reserved; /* Pad to capability size. */
	};

	/*
	 * Further fields are unknown to the assembly domain-transition code.
	 */
	struct sandbox_class	*sbo_sandbox_classp;
	struct sandbox_object	*sbo_sandbox_system_objectp;
	void			*sbo_datamem;
	void			*sbo_stackmem;

	register_t		 sbo_datalen;
	register_t		 sbo_heapbase;
	register_t		 sbo_heaplen;
	register_t		 sbo_stacklen;
	uint			 sbo_flags;	/* Sandbox flags. */

	/*
	 * Sealed code and data capabilities suitable to access the object's
	 * run-time linker methods and also general object-capability
	 * invocation.
	 */
	struct cheri_object	 sbo_cheri_object_rtld;
	struct cheri_object	 sbo_cheri_object_invoke;

	/*
	 * System-object capabilities that can be passed to the object via
	 * sandbox metadata.
	 */
	struct cheri_object	 sbo_cheri_object_system;

	/*
	 * Stack capability that will also be installed in the object during
	 * domain transition.
	 */
	__capability void	*sbo_stackcap;

	/*
	 * Sandbox statistics.
	 */
	struct sandbox_object_stat	*sbo_sandbox_object_statp;

	/*
	 * Private data for system objects -- e.g., for cheri_fd, a pointer to
	 * file-descriptor data.
	 */
	__capability void	*sbo_private_data;
};

/*
 * A classic 'sandbox' is actually a combination of a sandbox class and a
 * sandbox object.  We continue to support this model as it is used in some
 * CHERI demo and test code.
 */
struct sandbox {
	struct sandbox_class	*sb_sandbox_classp;
	struct sandbox_object	*sb_sandbox_objectp;
};

int	sandbox_class_load(struct sandbox_class *sbcp);
void	sandbox_class_unload(struct sandbox_class *sbcp);
int	sandbox_object_load(struct sandbox_class *sbcp,
	    struct sandbox_object *sbop);
int	sandbox_object_protect(struct sandbox_class *sbcp,
	    struct sandbox_object *sbop);
int	sandbox_object_reload(struct sandbox_object *sbop);
void	sandbox_object_unload(struct sandbox_object *sbop);

#endif /* !_SANDBOX_INTERNAL_H_ */
