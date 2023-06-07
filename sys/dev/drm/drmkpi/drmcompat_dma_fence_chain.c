/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Emmanuel Vadot <manu@FreeBSD.org>
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

#include <linux/dma-fence.h>
#include <linux/dma-fence-chain.h>

static const char *
dma_fence_chain_get_driver_name(struct dma_fence *fence)
{

	return "dma_fence_chain";
}

static const char *
dma_fence_chain_get_timeline_name(struct dma_fence *fence)
{

	return "unbound";
}

static bool
dma_fence_chain_enable_signaling(struct dma_fence *fence)
{

	return (false);
}

static bool
dma_fence_chain_signaled(struct dma_fence *fence)
{

	return (false);
}

static void
dma_fence_chain_release(struct dma_fence *fence)
{
}

const struct dma_fence_ops dma_fence_chain_ops = {
	.use_64bit_seqno = true,
	.get_driver_name = dma_fence_chain_get_driver_name,
	.get_timeline_name = dma_fence_chain_get_timeline_name,
	.enable_signaling = dma_fence_chain_enable_signaling,
	.signaled = dma_fence_chain_signaled,
	.release = dma_fence_chain_release,
};


struct dma_fence *
dma_fence_chain_walk(struct dma_fence *fence)
{

	return (NULL);
}

int
dma_fence_chain_find_seqno(struct dma_fence **pfence, uint64_t seqno)
{

	return (0);
}

void
dma_fence_chain_init(struct dma_fence_chain *chain,
    struct dma_fence *prev,
    struct dma_fence *fence,
    uint64_t seqno)
{

	return;
}
