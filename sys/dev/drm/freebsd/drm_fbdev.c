/*-
 * Copyright (c) 2013 Oleksandr Rybalko <ray@freebsd.org>
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

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_print.h>
#include <drm/drm_vblank.h>

#include <sys/kdb.h>
#include <sys/param.h>
#include <sys/systm.h>

/* Call restore out of vt(9) locks. */

static void
vt_restore_fbdev_mode(void *arg, int pending)
{
	struct drm_fb_helper *fb_helper;
	struct vt_kms_softc *sc;

	sc = (struct vt_kms_softc *)arg;
	fb_helper = sc->fb_helper;
	drm_fb_helper_restore_fbdev_mode_unlocked(fb_helper);
}

static int
vt_kms_postswitch(void *arg)
{
	struct vt_kms_softc *sc;

	sc = (struct vt_kms_softc *)arg;

	DRM_DEBUG("%s: called\n", __func__);

	if (!kdb_active && panicstr == NULL)
		taskqueue_enqueue(taskqueue_thread, &sc->fb_mode_task);
	else
		drm_fb_helper_restore_fbdev_mode_unlocked(sc->fb_helper);

	return (0);
}

struct fb_info *
framebuffer_alloc(size_t size, struct _device *dev)
{
	struct fb_info *info;
	struct vt_kms_softc *sc;

	info = malloc(sizeof(*info), DRM_MEM_KMS, M_WAITOK | M_ZERO);

	sc = malloc(sizeof(*sc), DRM_MEM_KMS, M_WAITOK | M_ZERO);
	TASK_INIT(&sc->fb_mode_task, 0, vt_restore_fbdev_mode, sc);

	info->fb_priv = sc;
	info->enter = &vt_kms_postswitch;

	return (info);
}

void
framebuffer_release(struct fb_info *info)
{

	free(info->fb_priv, DRM_MEM_KMS);
	free(info, DRM_MEM_KMS);
}

int
fb_get_options(const char *connector_name, char **option)
{
	char tunable[64];

	/*
	 * A user may use loader tunables to set a specific mode for the
	 * console. Tunables are read in the following order:
	 *     1. kern.vt.fb.modes.$connector_name
	 *     2. kern.vt.fb.default_mode
	 *
	 * Example of a mode specific to the LVDS connector:
	 *     kern.vt.fb.modes.LVDS="1024x768"
	 *
	 * Example of a mode applied to all connectors not having a
	 * connector-specific mode:
	 *     kern.vt.fb.default_mode="640x480"
	 */
	snprintf(tunable, sizeof(tunable), "kern.vt.fb.modes.%s",
	    connector_name);
	DRM_INFO("Connector %s: get mode from tunables:\n", connector_name);
	DRM_INFO("  - %s\n", tunable);
	DRM_INFO("  - kern.vt.fb.default_mode\n");
	*option = kern_getenv(tunable);
	if (*option == NULL)
		*option = kern_getenv("kern.vt.fb.default_mode");

	return (*option != NULL ? 0 : -ENOENT);
}
