/*-
 * Copyright (c) 2019 Emmanuel Vadot <manu@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/fbio.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/resource.h>
#include <machine/bus.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <dev/fdt/simplebus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_vblank.h>

#include "fb_if.h"
#include "aw_de2_mixer_if.h"

struct aw_de2_drm_softc {
	device_t		dev;

	struct drm_device	drm_dev;
	struct drm_fb_cma	*fb;
};

static struct ofw_compat_data compat_data[] = {
	{ "allwinner,sun50i-a64-display-engine",	1 },
	{ "allwinner,sun8i-h3-display-engine",		1 },
	{ NULL,				0 }
};

static int aw_de2_drm_probe(device_t dev);
static int aw_de2_drm_attach(device_t dev);
static int aw_de2_drm_detach(device_t dev);

/* DRM driver fops */
static const struct file_operations aw_de2_drm_drv_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.compat_ioctl = drm_compat_ioctl,
	.poll = drm_poll,
	.read = drm_read,
	.mmap = drm_gem_cma_mmap,
	/* .llseek = noop_llseek, */
};

static struct drm_driver aw_de2_drm_driver = {
	.driver_features = DRIVER_GEM | DRIVER_MODESET | DRIVER_ATOMIC | DRIVER_PRIME,

	/* Generic Operations */
	.lastclose = drm_fb_helper_lastclose,
	.fops = &aw_de2_drm_drv_fops,

	/* GEM Opeations */
	.dumb_create = drm_gem_cma_dumb_create,
	.gem_free_object = drm_gem_cma_free_object,
	.gem_vm_ops = &drm_gem_cma_vm_ops,

	.name			= "aw-de2-drm",
	.desc			= "Allwinner DE2 Display Engine",
	.date			= "20190215",
	.major			= 1,
	.minor			= 0,
};

static void
aw_de2_drm_output_poll_changed(struct drm_device *drm_dev)
{
	struct aw_de2_drm_softc *sc;

	sc = container_of(drm_dev, struct aw_de2_drm_softc, drm_dev);
	if (sc->fb != NULL)
		drm_fb_helper_hotplug_event(&sc->fb->fb_helper);
}

static const struct drm_mode_config_funcs aw_de2_drm_mode_config_funcs = {
	.atomic_check		= drm_atomic_helper_check,
	.atomic_commit		= drm_atomic_helper_commit,
	.output_poll_changed	= aw_de2_drm_output_poll_changed,
	.fb_create		= drm_gem_fb_create,
};

static struct drm_mode_config_helper_funcs aw_de2_drm_mode_config_helpers = {
	.atomic_commit_tail	= drm_atomic_helper_commit_tail_rpm,
};

static struct fb_info *
drm_fb_cma_helper_getinfo(device_t dev)
{
	struct aw_de2_drm_softc *sc;

	sc = device_get_softc(dev);
	if (sc->fb == NULL)
		return (NULL);
	return (sc->fb->fb_helper.fbdev);
}

static struct drm_fb_helper_funcs fb_helper_funcs = {
	.fb_probe = drm_fb_cma_probe,
};

static int
aw_de2_drm_fb_preinit(struct drm_device *drm_dev)
{
	struct drm_fb_cma *fb;
	struct aw_de2_drm_softc *sc;

	sc = container_of(drm_dev, struct aw_de2_drm_softc, drm_dev);

	fb = malloc(sizeof(*fb), DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	drm_fb_helper_prepare(drm_dev, &fb->fb_helper, &fb_helper_funcs);
	sc->fb = fb;

	return (0);
}

static int
aw_de2_drm_fb_init(struct drm_device *drm_dev)
{
	struct aw_de2_drm_softc *sc;
	int rv;

	sc = container_of(drm_dev, struct aw_de2_drm_softc, drm_dev);

	drm_dev->dev = sc->dev;

	rv = drm_fb_helper_init(drm_dev, &sc->fb->fb_helper,
	     drm_dev->mode_config.num_connector);
	if (rv != 0) {
		device_printf(drm_dev->dev,
		    "Cannot initialize frame buffer %d\n", rv);
		return (rv);
	}

	rv = drm_fb_helper_single_add_all_connectors(&sc->fb->fb_helper);
	if (rv != 0) {
		device_printf(drm_dev->dev, "Cannot add all connectors: %d\n",
		    rv);
		goto err_fini;
	}

	rv = drm_fb_helper_initial_config(&sc->fb->fb_helper, 32);
	if (rv != 0) {
		device_printf(drm_dev->dev,
		    "Cannot set initial config: %d\n", rv);
		goto err_fini;
	}

	return 0;

err_fini:
	drm_fb_helper_fini(&sc->fb->fb_helper);
	return (rv);
}

#ifdef NOTYET
static void
aw_de2_drm_fb_destroy(struct drm_device *drm_dev)
{
	struct fb_info *info;
	struct drm_fb_cma *fb;
	struct aw_de2_drm_softc *sc;

	sc = container_of(drm_dev, struct aw_de2_drm_softc, drm_dev);
	fb = sc->fb;
	if (fb == NULL)
		return;
	info = fb->fb_helper.fbdev;

	drm_framebuffer_remove(&fb->drm_fb);
	framebuffer_release(info);
	drm_fb_helper_fini(&fb->fb_helper);
	drm_framebuffer_cleanup(&fb->drm_fb);

	free(fb, DRM_MEM_DRIVER);
	sc->fb = NULL;
}
#endif

static void
aw_de2_drm_irq_hook(void *arg)
{
	struct aw_de2_drm_softc *sc;
	phandle_t node;
	device_t mixerdev;
	uint32_t *mixers;
	int rv, nmixers, i;

	sc = arg;

	node = ofw_bus_get_node(sc->dev);

	drm_mode_config_init(&sc->drm_dev);

	rv = drm_dev_init(&sc->drm_dev, &aw_de2_drm_driver,
	    sc->dev);
	if (rv != 0) {
		device_printf(sc->dev, "drm_dev_init(): %d\n", rv);
		return;
	}

	nmixers = OF_getencprop_alloc_multi(node, "allwinner,pipelines",
	    sizeof(*mixers), (void **)&mixers);
	if (nmixers <= 0) {
		device_printf(sc->dev, "Cannot find mixers in allwinner,pipelines property\n");
		goto fail;
	}

	/* Attach the mixer(s) */
	for (i = 0; i < nmixers; i++) {
		if (bootverbose)
			device_printf(sc->dev, "Lookup mixer with phandle %x\n",
			    mixers[i]);
		mixerdev = OF_device_from_xref(mixers[i]);
		if (mixerdev != NULL)
			AW_DE2_MIXER_CREATE_PIPELINE(mixerdev,
			    &sc->drm_dev);
		else
			device_printf(sc->dev, "Cannot find mixer with phandle %x\n",
			    mixers[i]);
	}

	aw_de2_drm_fb_preinit(&sc->drm_dev);

	drm_vblank_init(&sc->drm_dev, sc->drm_dev.mode_config.num_crtc);

	drm_mode_config_reset(&sc->drm_dev);
	sc->drm_dev.mode_config.max_width = 4096;
	sc->drm_dev.mode_config.max_height = 4096;
	sc->drm_dev.mode_config.funcs = &aw_de2_drm_mode_config_funcs;
	sc->drm_dev.mode_config.helper_private = &aw_de2_drm_mode_config_helpers;

	aw_de2_drm_fb_init(&sc->drm_dev);

	drm_kms_helper_poll_init(&sc->drm_dev);

	/* Finally register our drm device */
	rv = drm_dev_register(&sc->drm_dev, 0);
	if (rv < 0)
		goto fail;

	sc->drm_dev.irq_enabled = true;

	return;
fail:
	device_printf(sc->dev, "drm_dev_register(): %d\n", rv);
}

static int
aw_de2_drm_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Allwinner DE2 Display Engine");
	return (BUS_PROBE_DEFAULT);
}

static int
aw_de2_drm_attach(device_t dev)
{
	struct aw_de2_drm_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	config_intrhook_oneshot(&aw_de2_drm_irq_hook, sc);

	return (0);
}

static int
aw_de2_drm_detach(device_t dev)
{
	struct aw_de2_drm_softc *sc;

	sc = device_get_softc(dev);

	drm_dev_unregister(&sc->drm_dev);
	drm_kms_helper_poll_fini(&sc->drm_dev);
	drm_atomic_helper_shutdown(&sc->drm_dev);
	drm_mode_config_cleanup(&sc->drm_dev);

	return (0);
}

static device_method_t aw_de2_drm_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		aw_de2_drm_probe),
	DEVMETHOD(device_attach,	aw_de2_drm_attach),
	DEVMETHOD(device_detach,	aw_de2_drm_detach),

	DEVMETHOD(fb_getinfo,		drm_fb_cma_helper_getinfo),

	DEVMETHOD_END
};

static driver_t aw_de2_driver = {
	"aw_de2_drm",
	aw_de2_drm_methods,
	sizeof(struct aw_de2_drm_softc),
};

static devclass_t aw_de2_drm_devclass;

DRIVER_MODULE(aw_de2_drm, simplebus, aw_de2_driver, aw_de2_drm_devclass, 0, 0);
MODULE_DEPEND(aw_de2_drm, aw_de2, 1, 1, 1);
MODULE_DEPEND(aw_de2_drm, aw_de2_mixer, 1, 1, 1);
/* Bindings for fbd device. */
extern driver_t fbd_driver;
DRIVER_MODULE(fbd, aw_de2_drm, fbd_driver, 0, 0);
