/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Konrad Witaszczyk
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Office of
 * Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
 * with Secure Hardware (SWISH)").
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include "compartment_function.h"

void
compartment_function(void)
{

}

static int
compartment_function_modevent(module_t mod, int type, void *unused)
{

	switch (type) {
	case MOD_LOAD:
		return (0);
	case MOD_UNLOAD:
		return (0);
	default:
		return (EINVAL);
	}
}

static moduledata_t compartment_function_mod = {
	"compartment_function",
	compartment_function_modevent,
	0
};

MODULE_VERSION(compartment_function, 1);
#ifdef CHERI_COMPARTMENTALIZE_KERNEL
MODULE_POLICY(compartment_function, true);
#else
#ifndef CHERI_DONT_COMPARTMENTALIZE_KERNEL
#warning "Module will not be compartmentalized (CHERI_COMPARTMENTALIZE_KERNEL is missing)."
#endif
MODULE_POLICY(compartment_function, false);
#endif
DECLARE_MODULE(compartment_function, compartment_function_mod, SI_SUB_PSEUDO,
    SI_ORDER_ANY);
