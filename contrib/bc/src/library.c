/*
 * *****************************************************************************
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018-2023 Gavin D. Howard and contributors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * *****************************************************************************
 *
 * The public functions for libbc.
 *
 */

#if BC_ENABLE_LIBRARY

#include <setjmp.h>
#include <string.h>
#include <time.h>

#include <bcl.h>

#include <library.h>
#include <num.h>
#include <vm.h>

#ifndef _WIN32
#include <pthread.h>
#endif // _WIN32

// The asserts in this file are important to testing; in many cases, the test
// would not work without the asserts, so don't remove them without reason.
//
// Also, there are many uses of bc_num_clear() here; that is because numbers are
// being reused, and a clean slate is required.
//
// Also, there are a bunch of BC_UNSETJMP between calls to bc_num_init(). That
// is because locals are being initialized, and unlike bc proper, this code
// cannot assume that allocation failures are fatal. So we have to reset the
// jumps every time to ensure that the locals will be correct after jumping.

static BclTls* tls = NULL;
static BclTls tls_real;

BclError
bcl_start(void)
{
#ifndef _WIN32

	int r;

	if (tls != NULL) return BCL_ERROR_NONE;

	r = pthread_key_create(&tls_real, NULL);
	if (BC_ERR(r != 0)) return BCL_ERROR_FATAL_ALLOC_ERR;

#else // _WIN32

	if (tls != NULL) return BCL_ERROR_NONE;

	tls_real = TlsAlloc();
	if (BC_ERR(tls_real == TLS_OUT_OF_INDEXES))
	{
		return BCL_ERROR_FATAL_ALLOC_ERR;
	}

#endif // _WIN32

	tls = &tls_real;

	return BCL_ERROR_NONE;
}

/**
 * Sets the thread-specific data for the thread.
 * @param vm  The @a BcVm to set as the thread data.
 * @return    An error code, if any.
 */
static BclError
bcl_setspecific(BcVm* vm)
{
#ifndef _WIN32

	int r;

	assert(tls != NULL);

	r = pthread_setspecific(tls_real, vm);
	if (BC_ERR(r != 0)) return BCL_ERROR_FATAL_ALLOC_ERR;

#else // _WIN32

	bool r;

	assert(tls != NULL);

	r = TlsSetValue(tls_real, vm);
	if (BC_ERR(!r)) return BCL_ERROR_FATAL_ALLOC_ERR;

#endif // _WIN32

	return BCL_ERROR_NONE;
}

BcVm*
bcl_getspecific(void)
{
	BcVm* vm;

#ifndef _WIN32

	vm = pthread_getspecific(tls_real);

#else // _WIN32

	vm = TlsGetValue(tls_real);

#endif // _WIN32

	return vm;
}

BclError
bcl_init(void)
{
	BclError e = BCL_ERROR_NONE;
	BcVm* vm;

	assert(tls != NULL);

	vm = bcl_getspecific();
	if (vm != NULL)
	{
		assert(vm->refs >= 1);

		vm->refs += 1;

		return e;
	}

	vm = bc_vm_malloc(sizeof(BcVm));
	if (BC_ERR(vm == NULL)) return BCL_ERROR_FATAL_ALLOC_ERR;

	e = bcl_setspecific(vm);
	if (BC_ERR(e != BCL_ERROR_NONE))
	{
		free(vm);
		return e;
	}

	memset(vm, 0, sizeof(BcVm));

	vm->refs += 1;

	assert(vm->refs == 1);

	// Setting these to NULL ensures that if an error occurs, we only free what
	// is necessary.
	vm->ctxts.v = NULL;
	vm->jmp_bufs.v = NULL;
	vm->out.v = NULL;

	vm->abrt = false;
	vm->leading_zeroes = false;
	vm->digit_clamp = true;

	// The jmp_bufs always has to be initialized first.
	bc_vec_init(&vm->jmp_bufs, sizeof(sigjmp_buf), BC_DTOR_NONE);

	BC_FUNC_HEADER(vm, err);

	bc_vm_init();

	bc_vec_init(&vm->ctxts, sizeof(BclContext), BC_DTOR_NONE);
	bc_vec_init(&vm->out, sizeof(uchar), BC_DTOR_NONE);

	// We need to seed this in case /dev/random and /dev/urandm don't work.
	srand((unsigned int) time(NULL));
	bc_rand_init(&vm->rng);

err:

	// This is why we had to set them to NULL.
	if (BC_ERR(vm != NULL && vm->err))
	{
		if (vm->out.v != NULL) bc_vec_free(&vm->out);
		if (vm->jmp_bufs.v != NULL) bc_vec_free(&vm->jmp_bufs);
		if (vm->ctxts.v != NULL) bc_vec_free(&vm->ctxts);
		bcl_setspecific(NULL);
		free(vm);
	}

	BC_FUNC_FOOTER(vm, e);

	return e;
}

BclError
bcl_pushContext(BclContext ctxt)
{
	BclError e = BCL_ERROR_NONE;
	BcVm* vm = bcl_getspecific();

	BC_FUNC_HEADER(vm, err);

	bc_vec_push(&vm->ctxts, &ctxt);

err:
	BC_FUNC_FOOTER(vm, e);
	return e;
}

void
bcl_popContext(void)
{
	BcVm* vm = bcl_getspecific();

	if (vm->ctxts.len) bc_vec_pop(&vm->ctxts);
}

static BclContext
bcl_contextHelper(BcVm* vm)
{
	if (!vm->ctxts.len) return NULL;
	return *((BclContext*) bc_vec_top(&vm->ctxts));
}

BclContext
bcl_context(void)
{
	BcVm* vm = bcl_getspecific();
	return bcl_contextHelper(vm);
}

void
bcl_free(void)
{
	size_t i;
	BcVm* vm = bcl_getspecific();

	vm->refs -= 1;
	if (vm->refs) return;

	bc_rand_free(&vm->rng);
	bc_vec_free(&vm->out);

	for (i = 0; i < vm->ctxts.len; ++i)
	{
		BclContext ctxt = *((BclContext*) bc_vec_item(&vm->ctxts, i));
		bcl_ctxt_free(ctxt);
	}

	bc_vec_free(&vm->ctxts);

	bc_vm_atexit();

	free(vm);
	bcl_setspecific(NULL);
}

void
bcl_end(void)
{
#ifndef _WIN32

	// We ignore the return value.
	pthread_key_delete(tls_real);

#else // _WIN32

	// We ignore the return value.
	TlsFree(tls_real);

#endif // _WIN32

	tls = NULL;
}

void
bcl_gc(void)
{
	bc_vm_freeTemps();
}

bool
bcl_abortOnFatalError(void)
{
	BcVm* vm = bcl_getspecific();

	return vm->abrt;
}

void
bcl_setAbortOnFatalError(bool abrt)
{
	BcVm* vm = bcl_getspecific();

	vm->abrt = abrt;
}

bool
bcl_leadingZeroes(void)
{
	BcVm* vm = bcl_getspecific();

	return vm->leading_zeroes;
}

void
bcl_setLeadingZeroes(bool leadingZeroes)
{
	BcVm* vm = bcl_getspecific();

	vm->leading_zeroes = leadingZeroes;
}

bool
bcl_digitClamp(void)
{
	BcVm* vm = bcl_getspecific();

	return vm->digit_clamp;
}

void
bcl_setDigitClamp(bool digitClamp)
{
	BcVm* vm = bcl_getspecific();

	vm->digit_clamp = digitClamp;
}

BclContext
bcl_ctxt_create(void)
{
	BcVm* vm = bcl_getspecific();
	BclContext ctxt = NULL;

	BC_FUNC_HEADER(vm, err);

	// We want the context to be free of any interference of other parties, so
	// malloc() is appropriate here.
	ctxt = bc_vm_malloc(sizeof(BclCtxt));

	bc_vec_init(&ctxt->nums, sizeof(BcNum), BC_DTOR_BCL_NUM);
	bc_vec_init(&ctxt->free_nums, sizeof(BclNumber), BC_DTOR_NONE);

	ctxt->scale = 0;
	ctxt->ibase = 10;
	ctxt->obase = 10;

err:

	if (BC_ERR(vm->err && ctxt != NULL))
	{
		if (ctxt->nums.v != NULL) bc_vec_free(&ctxt->nums);
		free(ctxt);
		ctxt = NULL;
	}

	BC_FUNC_FOOTER_NO_ERR(vm);

	return ctxt;
}

void
bcl_ctxt_free(BclContext ctxt)
{
	bc_vec_free(&ctxt->free_nums);
	bc_vec_free(&ctxt->nums);
	free(ctxt);
}

void
bcl_ctxt_freeNums(BclContext ctxt)
{
	bc_vec_popAll(&ctxt->nums);
	bc_vec_popAll(&ctxt->free_nums);
}

size_t
bcl_ctxt_scale(BclContext ctxt)
{
	return ctxt->scale;
}

void
bcl_ctxt_setScale(BclContext ctxt, size_t scale)
{
	ctxt->scale = scale;
}

size_t
bcl_ctxt_ibase(BclContext ctxt)
{
	return ctxt->ibase;
}

void
bcl_ctxt_setIbase(BclContext ctxt, size_t ibase)
{
	if (ibase < BC_NUM_MIN_BASE) ibase = BC_NUM_MIN_BASE;
	else if (ibase > BC_NUM_MAX_IBASE) ibase = BC_NUM_MAX_IBASE;
	ctxt->ibase = ibase;
}

size_t
bcl_ctxt_obase(BclContext ctxt)
{
	return ctxt->obase;
}

void
bcl_ctxt_setObase(BclContext ctxt, size_t obase)
{
	ctxt->obase = obase;
}

BclError
bcl_err(BclNumber n)
{
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ERR(vm, ctxt);

	// Errors are encoded as (0 - error_code). If the index is in that range, it
	// is an encoded error.
	if (n.i >= ctxt->nums.len)
	{
		if (n.i > 0 - (size_t) BCL_ERROR_NELEMS) return (BclError) (0 - n.i);
		else return BCL_ERROR_INVALID_NUM;
	}
	else return BCL_ERROR_NONE;
}

/**
 * Inserts a BcNum into a context's list of numbers.
 * @param ctxt  The context to insert into.
 * @param n     The BcNum to insert.
 * @return      The resulting BclNumber from the insert.
 */
static BclNumber
bcl_num_insert(BclContext ctxt, BcNum* restrict n)
{
	BclNumber idx;

	// If there is a free spot...
	if (ctxt->free_nums.len)
	{
		BcNum* ptr;

		// Get the index of the free spot and remove it.
		idx = *((BclNumber*) bc_vec_top(&ctxt->free_nums));
		bc_vec_pop(&ctxt->free_nums);

		// Copy the number into the spot.
		ptr = bc_vec_item(&ctxt->nums, idx.i);
		memcpy(ptr, n, sizeof(BcNum));
	}
	else
	{
		// Just push the number onto the vector.
		idx.i = ctxt->nums.len;
		bc_vec_push(&ctxt->nums, n);
	}

	return idx;
}

BclNumber
bcl_num_create(void)
{
	BclError e = BCL_ERROR_NONE;
	BcNum n;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	bc_num_init(&n, BC_NUM_DEF_SIZE);

err:
	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, n, idx);

	return idx;
}

/**
 * Destructs a number and marks its spot as free.
 * @param ctxt  The context.
 * @param n     The index of the number.
 * @param num   The number to destroy.
 */
static void
bcl_num_dtor(BclContext ctxt, BclNumber n, BcNum* restrict num)
{
	assert(num != NULL && num->num != NULL);

	bcl_num_destruct(num);
	bc_vec_push(&ctxt->free_nums, &n);
}

void
bcl_num_free(BclNumber n)
{
	BcNum* num;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	assert(n.i < ctxt->nums.len);

	num = BC_NUM(ctxt, n);

	bcl_num_dtor(ctxt, n, num);
}

BclError
bcl_copy(BclNumber d, BclNumber s)
{
	BclError e = BCL_ERROR_NONE;
	BcNum* dest;
	BcNum* src;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ERR(vm, ctxt);

	BC_FUNC_HEADER(vm, err);

	assert(d.i < ctxt->nums.len && s.i < ctxt->nums.len);

	dest = BC_NUM(ctxt, d);
	src = BC_NUM(ctxt, s);

	assert(dest != NULL && src != NULL);
	assert(dest->num != NULL && src->num != NULL);

	bc_num_copy(dest, src);

err:
	BC_FUNC_FOOTER(vm, e);

	return e;
}

BclNumber
bcl_dup(BclNumber s)
{
	BclError e = BCL_ERROR_NONE;
	BcNum *src, dest;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	assert(s.i < ctxt->nums.len);

	src = BC_NUM(ctxt, s);

	assert(src != NULL && src->num != NULL);

	// Copy the number.
	bc_num_clear(&dest);
	bc_num_createCopy(&dest, src);

err:
	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, dest, idx);

	return idx;
}

void
bcl_num_destruct(void* num)
{
	BcNum* n = (BcNum*) num;

	assert(n != NULL);

	if (n->num == NULL) return;

	bc_num_free(num);
	bc_num_clear(num);
}

bool
bcl_num_neg(BclNumber n)
{
	BcNum* num;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	assert(n.i < ctxt->nums.len);

	num = BC_NUM(ctxt, n);

	assert(num != NULL && num->num != NULL);

	return BC_NUM_NEG(num) != 0;
}

void
bcl_num_setNeg(BclNumber n, bool neg)
{
	BcNum* num;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	assert(n.i < ctxt->nums.len);

	num = BC_NUM(ctxt, n);

	assert(num != NULL && num->num != NULL);

	num->rdx = BC_NUM_NEG_VAL(num, neg);
}

size_t
bcl_num_scale(BclNumber n)
{
	BcNum* num;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	assert(n.i < ctxt->nums.len);

	num = BC_NUM(ctxt, n);

	assert(num != NULL && num->num != NULL);

	return bc_num_scale(num);
}

BclError
bcl_num_setScale(BclNumber n, size_t scale)
{
	BclError e = BCL_ERROR_NONE;
	BcNum* nptr;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ERR(vm, ctxt);

	BC_CHECK_NUM_ERR(ctxt, n);

	BC_FUNC_HEADER(vm, err);

	assert(n.i < ctxt->nums.len);

	nptr = BC_NUM(ctxt, n);

	assert(nptr != NULL && nptr->num != NULL);

	if (scale > nptr->scale) bc_num_extend(nptr, scale - nptr->scale);
	else if (scale < nptr->scale) bc_num_truncate(nptr, nptr->scale - scale);

err:
	BC_FUNC_FOOTER(vm, e);

	return e;
}

size_t
bcl_num_len(BclNumber n)
{
	BcNum* num;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	assert(n.i < ctxt->nums.len);

	num = BC_NUM(ctxt, n);

	assert(num != NULL && num->num != NULL);

	return bc_num_len(num);
}

BclError
bcl_bigdig(BclNumber n, BclBigDig* result)
{
	BclError e = BCL_ERROR_NONE;
	BcNum* num;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ERR(vm, ctxt);

	BC_FUNC_HEADER(vm, err);

	assert(n.i < ctxt->nums.len);
	assert(result != NULL);

	num = BC_NUM(ctxt, n);

	assert(num != NULL && num->num != NULL);

	*result = bc_num_bigdig(num);

err:
	bcl_num_dtor(ctxt, n, num);
	BC_FUNC_FOOTER(vm, e);

	return e;
}

BclNumber
bcl_bigdig2num(BclBigDig val)
{
	BclError e = BCL_ERROR_NONE;
	BcNum n;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	bc_num_createFromBigdig(&n, val);

err:
	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, n, idx);

	return idx;
}

/**
 * Sets up and executes a binary operator operation.
 * @param a     The first operand.
 * @param b     The second operand.
 * @param op    The operation.
 * @param req   The function to get the size of the result for preallocation.
 * @return      The result of the operation.
 */
static BclNumber
bcl_binary(BclNumber a, BclNumber b, const BcNumBinaryOp op,
           const BcNumBinaryOpReq req)
{
	BclError e = BCL_ERROR_NONE;
	BcNum* aptr;
	BcNum* bptr;
	BcNum c;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_CHECK_NUM(ctxt, a);
	BC_CHECK_NUM(ctxt, b);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	assert(a.i < ctxt->nums.len && b.i < ctxt->nums.len);

	aptr = BC_NUM(ctxt, a);
	bptr = BC_NUM(ctxt, b);

	assert(aptr != NULL && bptr != NULL);
	assert(aptr->num != NULL && bptr->num != NULL);

	// Clear and initialize the result.
	bc_num_clear(&c);
	bc_num_init(&c, req(aptr, bptr, ctxt->scale));

	op(aptr, bptr, &c, ctxt->scale);

err:

	// Eat the operands.
	bcl_num_dtor(ctxt, a, aptr);
	if (b.i != a.i) bcl_num_dtor(ctxt, b, bptr);

	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, c, idx);

	return idx;
}

BclNumber
bcl_add(BclNumber a, BclNumber b)
{
	return bcl_binary(a, b, bc_num_add, bc_num_addReq);
}

BclNumber
bcl_sub(BclNumber a, BclNumber b)
{
	return bcl_binary(a, b, bc_num_sub, bc_num_addReq);
}

BclNumber
bcl_mul(BclNumber a, BclNumber b)
{
	return bcl_binary(a, b, bc_num_mul, bc_num_mulReq);
}

BclNumber
bcl_div(BclNumber a, BclNumber b)
{
	return bcl_binary(a, b, bc_num_div, bc_num_divReq);
}

BclNumber
bcl_mod(BclNumber a, BclNumber b)
{
	return bcl_binary(a, b, bc_num_mod, bc_num_divReq);
}

BclNumber
bcl_pow(BclNumber a, BclNumber b)
{
	return bcl_binary(a, b, bc_num_pow, bc_num_powReq);
}

BclNumber
bcl_lshift(BclNumber a, BclNumber b)
{
	return bcl_binary(a, b, bc_num_lshift, bc_num_placesReq);
}

BclNumber
bcl_rshift(BclNumber a, BclNumber b)
{
	return bcl_binary(a, b, bc_num_rshift, bc_num_placesReq);
}

BclNumber
bcl_sqrt(BclNumber a)
{
	BclError e = BCL_ERROR_NONE;
	BcNum* aptr;
	BcNum b;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_CHECK_NUM(ctxt, a);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	assert(a.i < ctxt->nums.len);

	aptr = BC_NUM(ctxt, a);

	bc_num_sqrt(aptr, &b, ctxt->scale);

err:
	bcl_num_dtor(ctxt, a, aptr);
	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, b, idx);

	return idx;
}

BclError
bcl_divmod(BclNumber a, BclNumber b, BclNumber* c, BclNumber* d)
{
	BclError e = BCL_ERROR_NONE;
	size_t req;
	BcNum* aptr;
	BcNum* bptr;
	BcNum cnum, dnum;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ERR(vm, ctxt);

	BC_CHECK_NUM_ERR(ctxt, a);
	BC_CHECK_NUM_ERR(ctxt, b);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 2);

	assert(c != NULL && d != NULL);

	aptr = BC_NUM(ctxt, a);
	bptr = BC_NUM(ctxt, b);

	assert(aptr != NULL && bptr != NULL);
	assert(aptr->num != NULL && bptr->num != NULL);

	bc_num_clear(&cnum);
	bc_num_clear(&dnum);

	req = bc_num_divReq(aptr, bptr, ctxt->scale);

	// Initialize the numbers.
	bc_num_init(&cnum, req);
	BC_UNSETJMP(vm);
	BC_SETJMP(vm, err);
	bc_num_init(&dnum, req);

	bc_num_divmod(aptr, bptr, &cnum, &dnum, ctxt->scale);

err:

	// Eat the operands.
	bcl_num_dtor(ctxt, a, aptr);
	if (b.i != a.i) bcl_num_dtor(ctxt, b, bptr);

	// If there was an error...
	if (BC_ERR(vm->err))
	{
		// Free the results.
		if (cnum.num != NULL) bc_num_free(&cnum);
		if (dnum.num != NULL) bc_num_free(&dnum);

		// Make sure the return values are invalid.
		c->i = 0 - (size_t) BCL_ERROR_INVALID_NUM;
		d->i = c->i;

		BC_FUNC_FOOTER(vm, e);
	}
	else
	{
		BC_FUNC_FOOTER(vm, e);

		// Insert the results into the context.
		*c = bcl_num_insert(ctxt, &cnum);
		*d = bcl_num_insert(ctxt, &dnum);
	}

	return e;
}

BclNumber
bcl_modexp(BclNumber a, BclNumber b, BclNumber c)
{
	BclError e = BCL_ERROR_NONE;
	size_t req;
	BcNum* aptr;
	BcNum* bptr;
	BcNum* cptr;
	BcNum d;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_CHECK_NUM(ctxt, a);
	BC_CHECK_NUM(ctxt, b);
	BC_CHECK_NUM(ctxt, c);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	assert(a.i < ctxt->nums.len && b.i < ctxt->nums.len);
	assert(c.i < ctxt->nums.len);

	aptr = BC_NUM(ctxt, a);
	bptr = BC_NUM(ctxt, b);
	cptr = BC_NUM(ctxt, c);

	assert(aptr != NULL && bptr != NULL && cptr != NULL);
	assert(aptr->num != NULL && bptr->num != NULL && cptr->num != NULL);

	// Prepare the result.
	bc_num_clear(&d);

	req = bc_num_divReq(aptr, cptr, 0);

	// Initialize the result.
	bc_num_init(&d, req);

	bc_num_modexp(aptr, bptr, cptr, &d);

err:

	// Eat the operands.
	bcl_num_dtor(ctxt, a, aptr);
	if (b.i != a.i) bcl_num_dtor(ctxt, b, bptr);
	if (c.i != a.i && c.i != b.i) bcl_num_dtor(ctxt, c, cptr);

	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, d, idx);

	return idx;
}

ssize_t
bcl_cmp(BclNumber a, BclNumber b)
{
	BcNum* aptr;
	BcNum* bptr;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	assert(a.i < ctxt->nums.len && b.i < ctxt->nums.len);

	aptr = BC_NUM(ctxt, a);
	bptr = BC_NUM(ctxt, b);

	assert(aptr != NULL && bptr != NULL);
	assert(aptr->num != NULL && bptr->num != NULL);

	return bc_num_cmp(aptr, bptr);
}

void
bcl_zero(BclNumber n)
{
	BcNum* nptr;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	assert(n.i < ctxt->nums.len);

	nptr = BC_NUM(ctxt, n);

	assert(nptr != NULL && nptr->num != NULL);

	bc_num_zero(nptr);
}

void
bcl_one(BclNumber n)
{
	BcNum* nptr;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	assert(n.i < ctxt->nums.len);

	nptr = BC_NUM(ctxt, n);

	assert(nptr != NULL && nptr->num != NULL);

	bc_num_one(nptr);
}

BclNumber
bcl_parse(const char* restrict val)
{
	BclError e = BCL_ERROR_NONE;
	BcNum n;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();
	bool neg;

	BC_CHECK_CTXT(vm, ctxt);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	assert(val != NULL);

	// We have to take care of negative here because bc's number parsing does
	// not.
	neg = (val[0] == '-');

	if (neg) val += 1;

	if (!bc_num_strValid(val))
	{
		vm->err = BCL_ERROR_PARSE_INVALID_STR;
		goto err;
	}

	// Clear and initialize the number.
	bc_num_clear(&n);
	bc_num_init(&n, BC_NUM_DEF_SIZE);

	bc_num_parse(&n, val, (BcBigDig) ctxt->ibase);

	// Set the negative.
	n.rdx = BC_NUM_NEG_VAL_NP(n, neg);

err:
	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, n, idx);

	return idx;
}

char*
bcl_string(BclNumber n)
{
	BcNum* nptr;
	char* str = NULL;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ASSERT(vm, ctxt);

	if (BC_ERR(n.i >= ctxt->nums.len)) return str;

	BC_FUNC_HEADER(vm, err);

	assert(n.i < ctxt->nums.len);

	nptr = BC_NUM(ctxt, n);

	assert(nptr != NULL && nptr->num != NULL);

	// Clear the buffer.
	bc_vec_popAll(&vm->out);

	// Print to the buffer.
	bc_num_print(nptr, (BcBigDig) ctxt->obase, false);
	bc_vec_pushByte(&vm->out, '\0');

	// Just dup the string; the caller is responsible for it.
	str = bc_vm_strdup(vm->out.v);

err:

	// Eat the operand.
	bcl_num_dtor(ctxt, n, nptr);

	BC_FUNC_FOOTER_NO_ERR(vm);

	return str;
}

BclNumber
bcl_irand(BclNumber a)
{
	BclError e = BCL_ERROR_NONE;
	BcNum* aptr;
	BcNum b;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_CHECK_NUM(ctxt, a);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	assert(a.i < ctxt->nums.len);

	aptr = BC_NUM(ctxt, a);

	assert(aptr != NULL && aptr->num != NULL);

	// Clear and initialize the result.
	bc_num_clear(&b);
	bc_num_init(&b, BC_NUM_DEF_SIZE);

	bc_num_irand(aptr, &b, &vm->rng);

err:

	// Eat the operand.
	bcl_num_dtor(ctxt, a, aptr);

	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, b, idx);

	return idx;
}

/**
 * Helps bcl_frand(). This is separate because the error handling is easier that
 * way. It is also easier to do ifrand that way.
 * @param b       The return parameter.
 * @param places  The number of decimal places to generate.
 */
static void
bcl_frandHelper(BcNum* restrict b, size_t places)
{
	BcNum exp, pow, ten;
	BcDig exp_digs[BC_NUM_BIGDIG_LOG10];
	BcDig ten_digs[BC_NUM_BIGDIG_LOG10];
	BcVm* vm = bcl_getspecific();

	// Set up temporaries.
	bc_num_setup(&exp, exp_digs, BC_NUM_BIGDIG_LOG10);
	bc_num_setup(&ten, ten_digs, BC_NUM_BIGDIG_LOG10);

	ten.num[0] = 10;
	ten.len = 1;

	bc_num_bigdig2num(&exp, (BcBigDig) places);

	// Clear the temporary that might need to grow.
	bc_num_clear(&pow);

	// Initialize the temporary that might need to grow.
	bc_num_init(&pow, bc_num_powReq(&ten, &exp, 0));

	BC_SETJMP(vm, err);

	// Generate the number.
	bc_num_pow(&ten, &exp, &pow, 0);
	bc_num_irand(&pow, b, &vm->rng);

	// Make the number entirely fraction.
	bc_num_shiftRight(b, places);

err:
	bc_num_free(&pow);
	BC_LONGJMP_CONT(vm);
}

BclNumber
bcl_frand(size_t places)
{
	BclError e = BCL_ERROR_NONE;
	BcNum n;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	// Clear and initialize the number.
	bc_num_clear(&n);
	bc_num_init(&n, BC_NUM_DEF_SIZE);

	bcl_frandHelper(&n, places);

err:

	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, n, idx);

	return idx;
}

/**
 * Helps bc_ifrand(). This is separate because error handling is easier that
 * way.
 * @param a       The limit for bc_num_irand().
 * @param b       The return parameter.
 * @param places  The number of decimal places to generate.
 */
static void
bcl_ifrandHelper(BcNum* restrict a, BcNum* restrict b, size_t places)
{
	BcNum ir, fr;
	BcVm* vm = bcl_getspecific();

	// Clear the integer and fractional numbers.
	bc_num_clear(&ir);
	bc_num_clear(&fr);

	// Initialize the integer and fractional numbers.
	bc_num_init(&ir, BC_NUM_DEF_SIZE);
	bc_num_init(&fr, BC_NUM_DEF_SIZE);

	BC_SETJMP(vm, err);

	bc_num_irand(a, &ir, &vm->rng);
	bcl_frandHelper(&fr, places);

	bc_num_add(&ir, &fr, b, 0);

err:
	bc_num_free(&fr);
	bc_num_free(&ir);
	BC_LONGJMP_CONT(vm);
}

BclNumber
bcl_ifrand(BclNumber a, size_t places)
{
	BclError e = BCL_ERROR_NONE;
	BcNum* aptr;
	BcNum b;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);
	BC_CHECK_NUM(ctxt, a);

	BC_FUNC_HEADER(vm, err);

	bc_vec_grow(&ctxt->nums, 1);

	assert(a.i < ctxt->nums.len);

	aptr = BC_NUM(ctxt, a);

	assert(aptr != NULL && aptr->num != NULL);

	// Clear and initialize the number.
	bc_num_clear(&b);
	bc_num_init(&b, BC_NUM_DEF_SIZE);

	bcl_ifrandHelper(aptr, &b, places);

err:

	// Eat the oprand.
	bcl_num_dtor(ctxt, a, aptr);

	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, b, idx);

	return idx;
}

BclError
bcl_rand_seedWithNum(BclNumber n)
{
	BclError e = BCL_ERROR_NONE;
	BcNum* nptr;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT_ERR(vm, ctxt);
	BC_CHECK_NUM_ERR(ctxt, n);

	BC_FUNC_HEADER(vm, err);

	assert(n.i < ctxt->nums.len);

	nptr = BC_NUM(ctxt, n);

	assert(nptr != NULL && nptr->num != NULL);

	bc_num_rng(nptr, &vm->rng);

err:
	BC_FUNC_FOOTER(vm, e);
	return e;
}

BclError
bcl_rand_seed(unsigned char seed[BCL_SEED_SIZE])
{
	BclError e = BCL_ERROR_NONE;
	size_t i;
	ulong vals[BCL_SEED_ULONGS];
	BcVm* vm = bcl_getspecific();

	BC_FUNC_HEADER(vm, err);

	// Fill the array.
	for (i = 0; i < BCL_SEED_SIZE; ++i)
	{
		ulong val = ((ulong) seed[i])
		            << (((ulong) CHAR_BIT) * (i % sizeof(ulong)));
		vals[i / sizeof(long)] |= val;
	}

	bc_rand_seed(&vm->rng, vals[0], vals[1], vals[2], vals[3]);

err:
	BC_FUNC_FOOTER(vm, e);
	return e;
}

void
bcl_rand_reseed(void)
{
	BcVm* vm = bcl_getspecific();

	bc_rand_srand(bc_vec_top(&vm->rng.v));
}

BclNumber
bcl_rand_seed2num(void)
{
	BclError e = BCL_ERROR_NONE;
	BcNum n;
	BclNumber idx;
	BclContext ctxt;
	BcVm* vm = bcl_getspecific();

	BC_CHECK_CTXT(vm, ctxt);

	BC_FUNC_HEADER(vm, err);

	// Clear and initialize the number.
	bc_num_clear(&n);
	bc_num_init(&n, BC_NUM_DEF_SIZE);

	bc_num_createFromRNG(&n, &vm->rng);

err:
	BC_FUNC_FOOTER(vm, e);
	BC_MAYBE_SETUP(ctxt, e, n, idx);

	return idx;
}

BclRandInt
bcl_rand_int(void)
{
	BcVm* vm = bcl_getspecific();

	return (BclRandInt) bc_rand_int(&vm->rng);
}

BclRandInt
bcl_rand_bounded(BclRandInt bound)
{
	BcVm* vm = bcl_getspecific();

	if (bound <= 1) return 0;
	return (BclRandInt) bc_rand_bounded(&vm->rng, (BcRand) bound);
}

#endif // BC_ENABLE_LIBRARY
