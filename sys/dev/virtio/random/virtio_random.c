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
#include <sys/module.h>
#include <sys/sglist.h>
#include <sys/callout.h>
#include <sys/random.h>
#include <sys/malloc.h>  /* Needed to include <dev/random/randomdev.h> */
#include <sys/lock.h>
#include <sys/mutex.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/random/random_harvestq.h>
#include <dev/random/randomdev.h>

struct vtrnd_softc {
	device_t		 vtrnd_dev;
	uint64_t		 vtrnd_features;
	struct callout		 vtrnd_callout;
	struct virtqueue	*vtrnd_vq;
};

static int	vtrnd_modevent(module_t, int, void *);

static int	vtrnd_probe(device_t);
static int	vtrnd_attach(device_t);
static int	vtrnd_detach(device_t);

static void	vtrnd_negotiate_features(struct vtrnd_softc *);
static int	vtrnd_alloc_virtqueue(struct vtrnd_softc *);
static void	vtrnd_harvest(struct vtrnd_softc *);
static void	vtrnd_timer(void *);

#define VTRND_FEATURES	0

static struct virtio_feature_desc vtrnd_feature_desc[] = {
	{ 0, NULL }
};

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

DRIVER_MODULE(virtio_random, virtio_pci, vtrnd_driver, vtrnd_devclass,
    vtrnd_modevent, 0);
MODULE_VERSION(virtio_random, 1);
MODULE_DEPEND(virtio_random, virtio, 1, 1, 1);

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

	if (virtio_get_device_type(dev) != VIRTIO_ID_ENTROPY)
		return (ENXIO);

	device_set_desc(dev, "VirtIO Entropy Adapter");

	return (BUS_PROBE_DEFAULT);
}

/* XXXAR: when we have virtio just use that to gather random data. This
 * speeds up ssh connections a lot since and should be fine for QEMU-CHERI */
#if defined(CPU_QEMU_MALTA)
#define USE_VIRTIO_AS_RANDOM_ALG 1
#define USE_VIRTIO_AS_RANDOM_SOURCE 0
#else
#define USE_VIRTIO_AS_RANDOM_ALG 0
#define USE_VIRTIO_AS_RANDOM_ALG 0
#endif


#if USE_VIRTIO_AS_RANDOM_SOURCE != 0 || USE_VIRTIO_AS_RANDOM_ALG != 0

static struct virtqueue *vq_global_hack = NULL;

static u_int random_virtio_read_impl(void *buf, u_int size) {
	struct sglist_seg segs[1];
	struct sglist sg;
	struct virtqueue *vq;
	int error;

	/* printf("%s(%p, %d)\n", __func__, buf, size); */
	explicit_bzero(buf, size);

	vq = vq_global_hack;
	if (!vq)
		return 0;

	sglist_init(&sg, 1, segs);
	error = sglist_append(&sg, buf, size);
	KASSERT(error == 0 && sg.sg_nseg == 1,
	    ("%s: error %d adding buffer to sglist", __func__, error));

	if (!virtqueue_empty(vq)) {
		printf("%s: Could not read %u bytes of random data -- virtqueue full\n", __func__, size);
		return 0;
	}
	if (virtqueue_enqueue(vq, buf, &sg, 0, 1) != 0) {
		printf("%s: Could not read %u bytes of random data -- virtqueue_enqueue failed\n", __func__, size);
		return 0;
	}

	/*
	 * Poll for the response, but the command is likely already
	 * done when we return from the notify.
	 */
	virtqueue_notify(vq);
	uint32_t len;
	virtqueue_poll(vq, &len);
	/* printf("%s: read %u bytes of random data (len = %d):\n", __func__, size, len); */
	return len;
}

#endif

#if USE_VIRTIO_AS_RANDOM_SOURCE != 0
static struct random_source random_virtio = {
	.rs_ident = "VIRTIO RNG",
	.rs_source = RANDOM_PURE_VIRTIO,
	.rs_read = random_virtio_read_impl,
};
#endif /* USE_VIRTIO_AS_RANDOM_SOURCE */

#if USE_VIRTIO_AS_RANDOM_ALG != 0
/* From other_algorith.m */
#define	RANDOM_RESEED_INIT_LOCK(x)		mtx_init(&random_virtio_mtx, "reseed mutex", NULL, MTX_DEF)
#define	RANDOM_RESEED_DEINIT_LOCK(x)		mtx_destroy(&random_virtio_mtx)
#define	RANDOM_RESEED_LOCK(x)			mtx_lock(&random_virtio_mtx)
#define	RANDOM_RESEED_UNLOCK(x)			mtx_unlock(&random_virtio_mtx)
#define	RANDOM_RESEED_ASSERT_LOCK_OWNED(x)	mtx_assert(&random_virtio_mtx, MA_OWNED)
/*
 * RANDOM_VIRTIO_NPOOLS is used when reading hardware random
 * number sources to ensure that each pool gets one read sample
 * per loop iteration. Yarrow has 2 such pools (FAST and SLOW),
 * and fortuna has 32 (0-31). The RNG used prior to Yarrow and
 * ported from Linux had just 1 pool.
 */
#define RANDOM_VIRTIO_NPOOLS 1
/* Use a mutex to protect your reseed variables? */
static struct mtx random_virtio_mtx;

static void
random_virtio_init_alg(void *unused __unused)
{
	RANDOM_RESEED_INIT_LOCK();
}

static void
random_virtio_deinit_alg(void *unused __unused)
{
	RANDOM_RESEED_DEINIT_LOCK();
}

static void
random_virtio_pre_read(void)
{

	RANDOM_RESEED_LOCK();
	/*
	 * Do pre-read housekeeping work here!
	 * You may use this as a chance to unblock the generator.
	 */
	RANDOM_RESEED_UNLOCK();
}

/*
 * void random_virtio_read(uint8_t *buf, u_int count)
 *
 * Generate <count> bytes of output into <*buf>.
 * You may use the fact that <count> will be a multiple of
 * RANDOM_BLOCKSIZE for optimization purposes.
 *
 * This function will always be called with your generator
 * unblocked and ready. If you are not ready to generate
 * output here, then feel free to KASSERT() or panic().
 */
static void
random_virtio_read(uint8_t *buf, u_int count)
{
	u_int read_bytes;

	RANDOM_RESEED_LOCK();
	/* XXXAR: how can we check how much data has been filled by QEMU? */
	read_bytes = random_virtio_read_impl(buf, count);
	/* printf("%s: read %u bytes of random data from virtio\n", __func__, read_bytes); */
	KASSERT(read_bytes == count,
	    ("Only read %d random bytes instead of %d", read_bytes, count));
	RANDOM_RESEED_UNLOCK();
}

/*
 * bool random_virtio_seeded(void)
 *
 * Return true if your generator is ready to generate
 * output, and false otherwise.
 */
static bool
random_virtio_seeded(void)
{
	/*
	 * Virtio random algorithm is always seeded (worst case the host will block).
	 * TODO: find out if we can query how much the host is willing to give
	 */
	return (true);
}

static void
random_virtio_process_event(struct harvest_event *event)
{
	/* Do nothing here */
}

struct random_algorithm virtio_random_alg_context = {
	.ra_ident = "VirtIO",
	.ra_init_alg = random_virtio_init_alg,
	.ra_deinit_alg = random_virtio_deinit_alg,
	.ra_pre_read = random_virtio_pre_read,
	.ra_read = random_virtio_read,
	.ra_seeded = random_virtio_seeded,
	.ra_event_processor = random_virtio_process_event,
	.ra_poolcount = RANDOM_VIRTIO_NPOOLS,
};

volatile struct random_algorithm *old_random_alg_context;

#endif /* USE_VIRTIO_AS_RANDOM_ALG */

static int
vtrnd_attach(device_t dev)
{
	struct vtrnd_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtrnd_dev = dev;

	callout_init(&sc->vtrnd_callout, 1);

	virtio_set_feature_desc(dev, vtrnd_feature_desc);
	vtrnd_negotiate_features(sc);

	error = vtrnd_alloc_virtqueue(sc);
	if (error) {
		device_printf(dev, "cannot allocate virtqueue\n");
		goto fail;
	}

#if USE_VIRTIO_AS_RANDOM_SOURCE != 0
	vq_global_hack = sc->vtrnd_vq;
	/*
	 * XXXAR: This causes the random thread to read tons entropy 10 times
	 * per second (but for QEMU I added a hack to only use it once).
	 * Also running the harvest every 5 seconds is completely pointless
	 * since it only gathers 16 bits of entropy...
	 */
	random_source_register(&random_virtio);
	(void)&vtrnd_timer;
	/* Let's read a bit more entropy to ensure we have enough for boot */
	read_rate_increment(10);
#elif USE_VIRTIO_AS_RANDOM_ALG != 0
	vq_global_hack = sc->vtrnd_vq;
	old_random_alg_context = p_random_alg_context;
	random_virtio_init_alg(NULL);
	p_random_alg_context = &virtio_random_alg_context;
	printf("%s: Updated random alg context\n", __func__);
	(void)&vtrnd_timer;
#else
	callout_reset(&sc->vtrnd_callout, 5 * hz, vtrnd_timer, sc);
#endif
fail:
	if (error)
		vtrnd_detach(dev);

	return (error);
}

static int
vtrnd_detach(device_t dev)
{
	struct vtrnd_softc *sc;

#if USE_VIRTIO_AS_RANDOM_SOURCE != 0
	vq_global_hack = NULL;
	random_source_deregister(&random_virtio);
#elif USE_VIRTIO_AS_RANDOM_ALG != 0
	vq_global_hack = NULL;
	random_virtio_deinit_alg(NULL);
	p_random_alg_context = old_random_alg_context;
#endif

	sc = device_get_softc(dev);

	callout_drain(&sc->vtrnd_callout);

	return (0);
}

static void
vtrnd_negotiate_features(struct vtrnd_softc *sc)
{
	device_t dev;
	uint64_t features;

	dev = sc->vtrnd_dev;
	features = VTRND_FEATURES;

	sc->vtrnd_features = virtio_negotiate_features(dev, features);
}

static int
vtrnd_alloc_virtqueue(struct vtrnd_softc *sc)
{
	device_t dev;
	struct vq_alloc_info vq_info;

	dev = sc->vtrnd_dev;

	VQ_ALLOC_INFO_INIT(&vq_info, 0, NULL, sc, &sc->vtrnd_vq,
	    "%s request", device_get_nameunit(dev));

	return (virtio_alloc_virtqueues(dev, 0, 1, &vq_info));
}

static void
vtrnd_harvest(struct vtrnd_softc *sc)
{
	struct sglist_seg segs[1];
	struct sglist sg;
	struct virtqueue *vq;
	uint64_t value;
	int error;

	vq = sc->vtrnd_vq;

	sglist_init(&sg, 1, segs);
	error = sglist_append(&sg, &value, sizeof(value));
	KASSERT(error == 0 && sg.sg_nseg == 1,
	    ("%s: error %d adding buffer to sglist", __func__, error));

	if (!virtqueue_empty(vq))
		return;
	if (virtqueue_enqueue(vq, &value, &sg, 0, 1) != 0)
		return;

	/*
	 * Poll for the response, but the command is likely already
	 * done when we return from the notify.
	 */
	virtqueue_notify(vq);
	virtqueue_poll(vq, NULL);

	random_harvest_queue(&value, sizeof(value), sizeof(value) * NBBY / 2,
	    RANDOM_PURE_VIRTIO);
}


static void
vtrnd_timer(void *xsc)
{
	struct vtrnd_softc *sc;

	sc = xsc;
	vtrnd_harvest(sc);
	callout_schedule(&sc->vtrnd_callout, 5 * hz);
}
