/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Andrew Turner
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
#include <sys/param.h>

#include <machine/cpu.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "static_tls.h"
#include "libc_private.h"

struct emutls_control {
	uint64_t size;
	uint64_t align;
	union {
		_Atomic size_t index;
		void *unused; /* Ensure this is pointer sized */
	};
	void *value_addr;
};

_Static_assert(sizeof(struct emutls_control) == (sizeof(uint64_t) * 2 +
    sizeof(void *) * 2), "emutls_control is the wrong size");

struct emutls_array {
	size_t size;
	void *data[];
};

/*
 * This cannot use pthread keys to store the per-thread emutls_array
 * since libthr depends on TLS.  Instead, emutls_head points to a
 * singly-linked list of emutls_array_list structures.  The static TLS
 * base of each thread is used as the key to identify which
 * emutls_array_list entry corresponds to each thread.
 */
struct emutls_array_list {
	struct emutls_array_list *next;
	struct emutls_array *array;
	uintptr_t handle;
};

static _Atomic uintptr_t emutls_head;

static _Atomic size_t emutls_next_index = 1;

static void *
emutls_alloc(size_t len)
{

	return (tls_calloc(len, 1));
}

static void *
emutls_memalign(size_t len, size_t align)
{

	if (align < sizeof(void *))
		align = sizeof(void *);
	return (tls_malloc_aligned(len, align));
}

static void
emutls_free(void *ptr)
{

	tls_free(ptr);
}

static void
emutls_setspecific(void *specific)
{
	struct emutls_array_list *cur;

	cur = (struct emutls_array_list *)atomic_load(&emutls_head);
	while (cur != NULL) {
		if (cur->handle == _libc_get_static_tls_base(0)) {
			cur->array = specific;
			return;
		}
		cur = cur->next;
	}

	cur = emutls_alloc(sizeof(*cur));
	if (cur == NULL)
		abort();
	cur->handle = _libc_get_static_tls_base(0);
	cur->array = specific;

	cur->next = (struct emutls_array_list *)atomic_load(&emutls_head);
	while (!atomic_compare_exchange_weak(&emutls_head,
	    (uintptr_t *)&cur->next, (uintptr_t)cur))
		cpu_spinwait();
}

static void *
emutls_getspecific(void)
{
	struct emutls_array_list *cur;

	cur = (struct emutls_array_list *)atomic_load(&emutls_head);
	while (cur != NULL) {
		if (cur->handle == _libc_get_static_tls_base(0))
			return (cur->array);
		cur = cur->next;
	}

	return (NULL);
}

/*
 * Get the array struct for this thread, ensuring it is large enough to
 * hold at least 'index' items
 */
static struct emutls_array *
emutls_get_array(size_t index)
{
	struct emutls_array *array, *new_array;
	size_t new_size;

	array = emutls_getspecific();
	if (array == NULL || index > array->size) {
		/*
		 * Allocate space for 16 values at a time to reduce
		 * the overhead of calling malloc + memcpy
		 */
		new_size = roundup2(index, 16);

		new_array = emutls_alloc(sizeof(struct emutls_array) +
		    sizeof(void *) * new_size);
		/* If this malloc fails there's not much we can do */
		if (new_array == NULL)
			abort();
		new_array->size = new_size;
		if (array != NULL) {
			/* Copy the old array to the new array */
			memcpy(&new_array->data, &array->data,
			    sizeof(void *) * array->size);
			emutls_free(array);
		}
		array = new_array;
		emutls_setspecific(array);
	}

	return (array);
}

/*
 * Allocate an index for this tsl value. The index is 1 based as 0 is special
 * under emutls to indicate the index is unallocated.
 */
static inline size_t
emutls_index(struct emutls_control* control)
{
	size_t index;

	index = atomic_load_explicit(&control->index, memory_order_acquire);
	if (index <= 0) {
		do {
			if (index > 0)
				return (index);
			/* If index < 0 another thread is allocating it */
			if (index < 0)
				cpu_spinwait();
			else if (atomic_compare_exchange_weak(&control->index,
			    &index, -1))
				break;
		} while (true);

		index = atomic_fetch_add(&emutls_next_index, 1);
		atomic_store_explicit(&control->index, index,
		    memory_order_release);
	}

	return (index);
}

void *
__emutls_get_address(struct emutls_control* control)
{
	struct emutls_array *array;
	size_t index;

	index = emutls_index(control);
	array = emutls_get_array(index);
	if (array->data[index - 1] == NULL) {
		array->data[index - 1] = emutls_memalign(control->size,
		    control->align);
		if (control->value_addr != 0)
			memcpy(array->data[index - 1],
			    control->value_addr, control->size);
	}

	return (array->data[index - 1]);
}
