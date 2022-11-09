/* Public domain. */

#ifndef _DRM_AGP_SUPPORT_
#define	_DRM_AGP_SUPPORT_

#include <dev/agp/agpvar.h>

struct drm_agp_head {
	struct list_head	memory;
	struct agp_info		agp_info;
	unsigned long		base;
	int			cant_use_aperture;
	int			agp_mtrr;
};

static inline void
drm_legacy_agp_clear(struct drm_device *dev)
{

	return;
}

#endif
