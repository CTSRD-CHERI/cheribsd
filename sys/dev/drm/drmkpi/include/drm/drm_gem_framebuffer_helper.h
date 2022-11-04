#ifndef __DRM_GEM_FB_HELPER_H__
#define __DRM_GEM_FB_HELPER_H__

struct drm_framebuffer *
drm_gem_fb_create(struct drm_device *drm, struct drm_file *file,
    const struct drm_mode_fb_cmd2 *cmd);

#endif
