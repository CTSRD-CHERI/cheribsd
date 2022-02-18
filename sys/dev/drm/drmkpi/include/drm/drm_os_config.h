#ifndef DRM_OS_CONFIG_H_
#define DRM_OS_CONFIG_H_

#ifdef _KERNEL
#define	__KERNEL__
#endif

#define COMPAT_FREEBSD32 1
#define CONFIG_COMPAT 1

#define	CONFIG_FB			1
#define	CONFIG_DRM_FBDEV_EMULATION	1
#define	CONFIG_DRM_LEGACY		0
#define	CONFIG_DRM_VM			0
#define CONFIG_AGP			0
#define CONFIG_DRM_FBDEV_LEAK_PHYS_SMEM	0

// Overallocation of the fbdev buffer
// Defines the fbdev buffer overallocation in percent. Default is 100.
// Typical values for double buffering will be 200, triple buffering 300.
#define CONFIG_DRM_FBDEV_OVERALLOC 100


#endif
