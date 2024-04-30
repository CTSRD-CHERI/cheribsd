/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2008,	Jeffrey Roberson <jeff@freebsd.org>
 * All rights reserved.
 *
 * Copyright (c) 2008 Nokia Corporation
 * All rights reserved.
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

// Data Buffer Information
struct ctrl_reg {
	// Address offset
	long offset;
	// Address size
	// int addr_width;
	// Buffer size
	int size;
	// Buffer pointer
	void *ptr;
};

// HLS Kernel Information
struct accel_ctrl_args {
	// Pointer to the accelerator
	void *which;
	// Data buffer count
	int buffer_count;
	// Data buffer information
	ctrl_reg *buffers;
};

int accel_malloc(struct accel_ctrl_args *accel_config);
int accel_demalloc(struct accel_ctrl_args *accel_config);

// JC TODO: Where to put following code?
// JC TODO: Address translation?
u64 accel_addr[8] = { 0xC0010000, 0xC0011000, 0xC0012000, 0xC0013000,
	0xC0014000, 0xC0015000, 0xC0016000, 0xC0017000 };
bool accel_states[8] = { 0 };

int
accel_malloc(struct accel_ctrl_args *accel_config)
{
	int index = -1;
	for (int i = 0; i < 8; i++)
		if (!accel_states[i]) {
			accel_states[i] = 1;
			index = i;
			break;
		}
	if (index == -1)
		return -1;

	// Allocate accelerator process
	// JC: May need to use CHERI APIs
	volatile u32 *accel_ptr = base_phy_addr[index];
	accel_config->which = accel_ptr;

	for (int i = 0; i < accel_config->buffer_count; i++) {
		cntrl_reg *buffer = accel_config->buffers + i;

		// Allocate buffer
		u32 *data = (int *)malloc(buffer->size * sizeof(int));
		buff->ptr = data;

		// Write to control registers
		*(volatile u32 *)(accel_ptr +
		    (buffer->offset >> 2)) = (u32)data;
	}

	return 0;
}

int
accel_demalloc(struct accel_ctrl_args *accel_config)
{

	volatile int accel_ptr = accel_config->which;

	int index = -1;
	for (int i = 0; i < 8; i++)
		if (accel_addr[i] == accel_ptr && accel_states[i]) {
			accel_states[i] = 0;
			index = i;
			break;
		}
	if (index == -1)
		return -1;

	// Deallocate accelerator process
	// JC: May need to use CHERI APIs
	for (int i = 0; i < accel_config->buffer_count; i++) {
		cntrl_reg *buffer = accel_config->buffers + i;

		// Deallocate buffer
		free(buff->ptr);
	}

	return 0;
}

#endif
