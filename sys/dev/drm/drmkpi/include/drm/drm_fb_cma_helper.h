#ifndef _DRM_FB_CMA_HELPER_H_
#define	 _DRM_FB_CMA_HELPER_H_

#include <drm/drm_fb_helper.h>

struct drm_fb_cma {
	struct drm_framebuffer	drm_fb __subobject_member_used_for_c_inheritance;
	struct drm_fb_helper	fb_helper;

	struct drm_gem_cma_object	**planes;	/* Attached planes */
	vm_pointer_t		*planes_vbase;
	int			nplanes;
} __subobject_use_container_bounds;

struct drm_gem_cma_object *drm_fb_cma_get_gem_obj(struct drm_fb_cma *fb, int idx);
int drm_fb_cma_probe(struct drm_fb_helper *helper, struct drm_fb_helper_surface_size *sizes);

#endif /* _DRM_FB_CMA_HELPER_H_ */
