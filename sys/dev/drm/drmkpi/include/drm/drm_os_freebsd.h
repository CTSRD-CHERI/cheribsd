/**
 * \file drm_os_freebsd.h
 * OS abstraction macros.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#ifndef _DRM_OS_FREEBSD_H_
#define	_DRM_OS_FREEBSD_H_

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/fbio.h>
#include <sys/malloc.h>

#include "drm_os_config.h"

#define PICOS2KHZ(a) (1000000000UL/(a))
#define KHZ2PICOS(a) (1000000000UL/(a))

#define DRM_DEV_MODE	(S_IRUSR|S_IWUSR|S_IROTH|S_IWOTH|S_IRGRP|S_IWGRP)
#define DRM_DEV_UID	UID_ROOT
#define DRM_DEV_GID	GID_VIDEO

#define	KTR_DRM		KTR_DEV
#define	KTR_DRM_REG	KTR_SPARE3

MALLOC_DECLARE(DRM_MEM_DRIVER);
MALLOC_DECLARE(DRM_MEM_KMS);

struct drm_minor;
struct drm_device;
int drm_fbsd_cdev_create(struct drm_minor *minor);
void drm_fbsd_cdev_delete(struct drm_minor *minor);
int drm_fbsd_sysctl_cleanup(struct drm_device *dev);
int drm_fbsd_sysctl_init(struct drm_device *dev);

#endif /* _DRM_OS_FREEBSD_H_ */
