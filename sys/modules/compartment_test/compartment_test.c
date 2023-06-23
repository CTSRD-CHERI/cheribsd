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
#include <sys/compartment.h>
#include <sys/compressor.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/sx.h>

#include <modules/compartment_function/compartment_function.h>

SYSCTL_NODE(_security_compartment, OID_AUTO, test, CTLFLAG_RD, 0,
    "Compartment test cases");

static uintptr_t compartment_entry_funptr;

#define	SYSCTL_ENTRY_INIT	0
#define	SYSCTL_ENTRY_CALL	1
#define	SYSCTL_ENTRY_FINI	2
#define	SYSCTL_COMPRESSOR_INIT	3
#define	SYSCTL_COMPRESSOR_WRITE	4
#define	SYSCTL_COMPRESSOR_FLUSH	5
#define	SYSCTL_COMPRESSOR_FINI	6

static uint8_t compressor_data[PAGE_SIZE];
static struct compressor *compressor_stream;

static int
compartment_test_compressor_cb(void *base __unused, size_t length __unused,
    off_t offset __unused, void *arg __unused)
{

	return (0);
}

static int
compartment_test_sysctl(int function, SYSCTL_HANDLER_ARGS)
{
	int error, ii;
	unsigned int value;
	uintptr_t funptr;
	module_t mod;

	value = 0;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error)
		return (error);
	if (req->newptr == NULL) {
		goto out;
	}

	switch (function) {
	case SYSCTL_ENTRY_INIT:
		if (compartment_entry_funptr != (uintptr_t)NULL)
			return (EINVAL);

		funptr = (uintptr_t)compartment_function;

		MOD_SLOCK;
		mod = module_lookupbyptr(funptr);
		if (mod == NULL)
			return (EINVAL);
		if (module_getpolicy(mod)) {
			funptr = (uintptr_t)compartment_entry_for_module(mod,
			    funptr);
		}
		MOD_SUNLOCK;

		compartment_entry_funptr = funptr;
		break;
	case SYSCTL_ENTRY_CALL:
		if (compartment_entry_funptr == (uintptr_t)NULL)
			return (EINVAL);
		for (ii = 0; ii < value; ii++)
			((void (*)(void))compartment_entry_funptr)();
		break;
	case SYSCTL_ENTRY_FINI:
		if (compartment_entry_funptr == (uintptr_t)NULL)
			return (EINVAL);
		compartment_trampoline_destroy(compartment_entry_funptr);
		compartment_entry_funptr = (uintptr_t)NULL;
		break;
	case SYSCTL_COMPRESSOR_INIT:
		if (compressor_stream != NULL)
			return (EINVAL);
		compressor_stream = compressor_init(
		    compartment_jump((uintptr_t)compartment_test_compressor_cb),
		    COMPRESS_ZLIB_DEFLATE, sizeof(compressor_data), 0, NULL);
		if (compressor_stream == NULL) {
			error = ENOMEM;
		}
		break;
	case SYSCTL_COMPRESSOR_WRITE:
		if (compressor_stream == NULL)
			return (EINVAL);
		for (ii = 0; ii < value; !error && ii++) {
			error = compressor_write(compressor_stream,
			    &compressor_data, sizeof(compressor_data));
		}
		break;
	case SYSCTL_COMPRESSOR_FLUSH:
		if (compressor_stream == NULL)
			return (EINVAL);
		error = compressor_flush(compressor_stream);
		break;
	case SYSCTL_COMPRESSOR_FINI:
		if (compressor_stream == NULL)
			return (EINVAL);
		compressor_fini(compressor_stream);
		compressor_stream = NULL;
		break;
	default:
		return (EINVAL);
	}

out:
	if (error != 0)
		return (error);
	return (SYSCTL_OUT(req, &value, sizeof(value)));
}

static int
compartment_test_entry_init(SYSCTL_HANDLER_ARGS)
{

	return (compartment_test_sysctl(SYSCTL_ENTRY_INIT,
	    oidp, arg1, arg2, req));
}

static int
compartment_test_entry_call(SYSCTL_HANDLER_ARGS)
{

	return (compartment_test_sysctl(SYSCTL_ENTRY_CALL,
	    oidp, arg1, arg2, req));
}

static int
compartment_test_entry_fini(SYSCTL_HANDLER_ARGS)
{

	return (compartment_test_sysctl(SYSCTL_ENTRY_FINI,
	    oidp, arg1, arg2, req));
}

static int
compartment_test_compressor_init(SYSCTL_HANDLER_ARGS)
{

	return (compartment_test_sysctl(SYSCTL_COMPRESSOR_INIT,
	    oidp, arg1, arg2, req));
}

static int
compartment_test_compressor_write(SYSCTL_HANDLER_ARGS)
{

	return (compartment_test_sysctl(SYSCTL_COMPRESSOR_WRITE,
	    oidp, arg1, arg2, req));
}

static int
compartment_test_compressor_flush(SYSCTL_HANDLER_ARGS)
{

	return (compartment_test_sysctl(SYSCTL_COMPRESSOR_FLUSH,
	    oidp, arg1, arg2, req));
}

static int
compartment_test_compressor_fini(SYSCTL_HANDLER_ARGS)
{

	return (compartment_test_sysctl(SYSCTL_COMPRESSOR_FINI,
	    oidp, arg1, arg2, req));
}

SYSCTL_NODE(_security_compartment_test, OID_AUTO, entry, CTLFLAG_RD, 0,
    "Compartment test cases for entries");
SYSCTL_PROC(_security_compartment_test_entry, OID_AUTO, init,
    CTLTYPE_UINT | CTLFLAG_RWTUN, 0, 0, compartment_test_entry_init, "IU",
    "Initialize a compartment entry");
SYSCTL_PROC(_security_compartment_test_entry, OID_AUTO, call,
    CTLTYPE_UINT | CTLFLAG_RWTUN, 0, 0, compartment_test_entry_call, "IU",
    "Call a compartment entry");
SYSCTL_PROC(_security_compartment_test_entry, OID_AUTO, fini,
    CTLTYPE_UINT | CTLFLAG_RWTUN, 0, 0, compartment_test_entry_fini, "IU",
    "Finalize a compartment entry");

SYSCTL_NODE(_security_compartment_test, OID_AUTO, compressor, CTLFLAG_RD, 0,
    "Compartment test cases for compressor");
SYSCTL_PROC(_security_compartment_test_compressor, OID_AUTO, init,
    CTLTYPE_UINT | CTLFLAG_RWTUN, 0, 0, compartment_test_compressor_init, "IU",
    "Call a compartment entry for a compressor init function");
SYSCTL_PROC(_security_compartment_test_compressor, OID_AUTO, write,
    CTLTYPE_UINT | CTLFLAG_RWTUN, 0, 0, compartment_test_compressor_write, "IU",
    "Call a compartment entry for a compressor write function N times");
SYSCTL_PROC(_security_compartment_test_compressor, OID_AUTO, flush,
    CTLTYPE_UINT | CTLFLAG_RWTUN, 0, 0, compartment_test_compressor_flush, "IU",
    "Call a compartment entry for a compressor flush function");
SYSCTL_PROC(_security_compartment_test_compressor, OID_AUTO, fini,
    CTLTYPE_UINT | CTLFLAG_RWTUN, 0, 0, compartment_test_compressor_fini, "IU",
    "Call a compartment entry for a compressor fini function");

static int
compartment_test_modevent(module_t mod, int type, void *unused)
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

static moduledata_t compartment_test_mod = {
	"compartment_test",
	compartment_test_modevent,
	0
};

MODULE_VERSION(compartment_test, 1);
MODULE_DEPEND(compartment_test, compartment_function, 1, 1, 1);
DECLARE_MODULE(compartment_test, compartment_test_mod, SI_SUB_PSEUDO,
    SI_ORDER_ANY);
