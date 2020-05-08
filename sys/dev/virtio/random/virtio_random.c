/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2013, Bryan Venteicher <bryanv@FreeBSD.org>
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
 */

/* Driver for VirtIO entropy device. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sglist.h>
#include <sys/callout.h>
#include <sys/random.h>
#include <sys/stdatomic.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>

#include <dev/random/randomdev.h>
#include <dev/random/random_harvestq.h>
#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>

struct vtrnd_softc {
	uint64_t		 vtrnd_features;
	struct virtqueue	*vtrnd_vq;
};

static int	vtrnd_modevent(module_t, int, void *);

static int	vtrnd_probe(device_t);
static int	vtrnd_attach(device_t);
static int	vtrnd_detach(device_t);

static void	vtrnd_negotiate_features(device_t);
static int	vtrnd_alloc_virtqueue(device_t);
static int	vtrnd_harvest(struct vtrnd_softc *, void *, size_t *);
static unsigned	vtrnd_read(void *, unsigned);

#define VTRND_FEATURES	0

static struct virtio_feature_desc vtrnd_feature_desc[] = {
	{ 0, NULL }
};

static struct random_source random_vtrnd = {
	.rs_ident = "VirtIO Entropy Adapter",
	.rs_source = RANDOM_PURE_VIRTIO,
	.rs_read = vtrnd_read,
};

/* Kludge for API limitations of random(4). */
static _Atomic(struct vtrnd_softc *) g_vtrnd_softc;

static device_method_t vtrnd_methods[] = {
	/* Device methods. */
	DEVMETHOD(device_probe,		vtrnd_probe),
	DEVMETHOD(device_attach,	vtrnd_attach),
	DEVMETHOD(device_detach,	vtrnd_detach),

	DEVMETHOD_END
};

static driver_t vtrnd_driver = {
	"vtrnd",
	vtrnd_methods,
	sizeof(struct vtrnd_softc)
};
static devclass_t vtrnd_devclass;

DRIVER_MODULE(virtio_random, virtio_mmio, vtrnd_driver, vtrnd_devclass,
    vtrnd_modevent, 0);
DRIVER_MODULE(virtio_random, virtio_pci, vtrnd_driver, vtrnd_devclass,
    vtrnd_modevent, 0);
MODULE_VERSION(virtio_random, 1);
MODULE_DEPEND(virtio_random, virtio, 1, 1, 1);
MODULE_DEPEND(virtio_random, random_device, 1, 1, 1);

VIRTIO_SIMPLE_PNPTABLE(virtio_random, VIRTIO_ID_ENTROPY,
    "VirtIO Entropy Adapter");
VIRTIO_SIMPLE_PNPINFO(virtio_mmio, virtio_random);
VIRTIO_SIMPLE_PNPINFO(virtio_pci, virtio_random);

static int
vtrnd_modevent(module_t mod, int type, void *unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
	case MOD_QUIESCE:
	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static int
vtrnd_probe(device_t dev)
{
	return (VIRTIO_SIMPLE_PROBE(dev, virtio_random));
}

static int
vtrnd_attach(device_t dev)
{
	struct vtrnd_softc *sc, *exp;
	int error;

	sc = device_get_softc(dev);

	virtio_set_feature_desc(dev, vtrnd_feature_desc);
	vtrnd_negotiate_features(dev);

	error = vtrnd_alloc_virtqueue(dev);
	if (error) {
		device_printf(dev, "cannot allocate virtqueue\n");
		goto fail;
	}

	exp = NULL;
	if (!atomic_compare_exchange_strong_explicit(&g_vtrnd_softc, &exp, sc,
	    memory_order_release, memory_order_acquire)) {
		error = EEXIST;
		goto fail;
	}
	random_source_register(&random_vtrnd);

fail:
	if (error)
		vtrnd_detach(dev);

	return (error);
}

static int
vtrnd_detach(device_t dev)
{
	struct vtrnd_softc *sc;

	sc = device_get_softc(dev);
	KASSERT(
	    atomic_load_explicit(&g_vtrnd_softc, memory_order_acquire) == sc,
	    ("only one global instance at a time"));

	random_source_deregister(&random_vtrnd);
	atomic_store_explicit(&g_vtrnd_softc, NULL, memory_order_release);
	return (0);
}

static void
vtrnd_negotiate_features(device_t dev)
{
	struct vtrnd_softc *sc;

	sc = device_get_softc(dev);
	sc->vtrnd_features = virtio_negotiate_features(dev, VTRND_FEATURES);
}

static int
vtrnd_alloc_virtqueue(device_t dev)
{
	struct vtrnd_softc *sc;
	struct vq_alloc_info vq_info;

	sc = device_get_softc(dev);

	VQ_ALLOC_INFO_INIT(&vq_info, 0, NULL, sc, &sc->vtrnd_vq,
	    "%s request", device_get_nameunit(dev));

	return (virtio_alloc_virtqueues(dev, 0, 1, &vq_info));
}

static int
vtrnd_harvest(struct vtrnd_softc *sc, void *buf, size_t *sz)
{
	struct sglist_seg segs[1];
	struct sglist sg;
	struct virtqueue *vq;
	uint32_t value[HARVESTSIZE] __aligned(sizeof(uint32_t) * HARVESTSIZE);
	uint32_t rdlen;
	int error;

	_Static_assert(sizeof(value) < PAGE_SIZE, "sglist assumption");

	sglist_init(&sg, 1, segs);
	error = sglist_append(&sg, value, *sz);
	if (error != 0)
		panic("%s: sglist_append error=%d", __func__, error);

	vq = sc->vtrnd_vq;
	KASSERT(virtqueue_empty(vq), ("%s: non-empty queue", __func__));

	error = virtqueue_enqueue(vq, buf, &sg, 0, 1);
	if (error != 0)
		return (error);

	/*
	 * Poll for the response, but the command is likely already
	 * done when we return from the notify.
	 */
	virtqueue_notify(vq);
	virtqueue_poll(vq, &rdlen);

	if (rdlen > *sz)
		panic("%s: random device wrote %zu bytes beyond end of provided"
		    " buffer %p:%zu", __func__, (size_t)rdlen - *sz,
		    (void *)value, *sz);
	else if (rdlen == 0)
		return (EAGAIN);
	*sz = MIN(rdlen, *sz);
	memcpy(buf, value, *sz);
	explicit_bzero(value, *sz);
	return (0);
}

static unsigned
vtrnd_read(void *buf, unsigned usz)
{
	struct vtrnd_softc *sc;
	size_t sz;
	int error;

	sc = g_vtrnd_softc;
	if (sc == NULL)
		return (0);

	sz = usz;
	error = vtrnd_harvest(sc, buf, &sz);
	if (error != 0)
		return (0);

	return (sz);
}
