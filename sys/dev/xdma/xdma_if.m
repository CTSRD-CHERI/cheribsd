#-
# Copyright (c) 2016 Ruslan Bukin <br@bsdpad.com>
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#

#include <machine/bus.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/xdma/xdma.h>

INTERFACE xdma;

#
# Prepare a channel for cyclic transfer.
#
METHOD int channel_prep_cyclic {
	device_t		dev;
	struct xdma_channel	*xchan;
};

#
# Prepare a channel for memcpy transfer.
#
METHOD int channel_prep_memcpy {
	device_t		dev;
	struct xdma_channel	*xchan;
};

#
# Notify driver we have machine-dependend data.
#
METHOD int ofw_md_data {
	device_t dev;
	pcell_t *cells;
	int ncells;
	void **data;
};

#
# Allocate both virtual and harware channels.
#
METHOD int channel_alloc {
	device_t dev;
	struct xdma_channel *xchan;
};

#
# Free the channel, including descriptors.
#
METHOD int channel_free {
	device_t dev;
	struct xdma_channel *xchan;
};

#
# Begin, pause or terminate the channel operation.
#
METHOD int channel_control {
	device_t dev;
	struct xdma_channel *xchan;
	int cmd;
};
