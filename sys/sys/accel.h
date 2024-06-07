/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _SYS_ACCEL_H_
#define _SYS_ACCEL_H_

#include <sys/cdefs.h>

struct thread;

// Data Buffer Information
struct buffer_config {
	// Address offset
	int offset;
	// Address size
	int addr_width;
	// Buffer size
	int size;
	// Buffer data
	int *data;
};

struct accel_config {
	// Data buffer count
	int buffer_count;
	// Data buffer information
	struct buffer_config *buffers;
};

// HLS Kernel Information
struct accel_ctrl_args {
	// Pointer to the accelerator
	int accel_count;
	// Accelerator configurations
	struct accel_config *accels;
};

// -----

int *init_buffer_config(struct buffer_config *bc, int o, int w, int b);
struct buffer_config *set_buffer_count(struct accel_config *x, int c);
int get_buffer_count(struct accel_config *x);
struct buffer_config *get_buffer_config(struct accel_config *x, int i);
struct accel_config *set_accel_count(struct accel_ctrl_args *x, int c);
struct accel_config *get_accel_config(struct accel_ctrl_args *x, int i);
int *get_buffer_data_ptr(struct buffer_config *bc);
int get_buffer_size(struct buffer_config *bc);

// ------

int *
init_buffer_config(struct buffer_config *bc, int o, int w, int b)
{
	bc->offset = o;
	bc->addr_width = w;
	bc->size = b;
	return bc->data;
}

struct buffer_config *
set_buffer_count(struct accel_config *x, int c)
{
	x->buffer_count = c;
	return x->buffers;
}

int
get_buffer_count(struct accel_config *x)
{
	return x->buffer_count;
}

struct buffer_config *
get_buffer_config(struct accel_config *x, int i)
{
	return x->buffers + i;
}

struct accel_config *
set_accel_count(struct accel_ctrl_args *x, int c)
{
	x->accel_count = c;
	return x->accels;
}

struct accel_config *
get_accel_config(struct accel_ctrl_args *x, int i)
{
	return x->accels + i;
}

int *
get_buffer_data_ptr(struct buffer_config *bc)
{
	return bc->data;
}

int
get_buffer_size(struct buffer_config *bc)
{
	return bc->size;
}

#endif
