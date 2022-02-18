#ifndef __DRMCOMPAT_LINUX_PLATFORM_DEVICE_H__
#define	__DRMCOMPAT_LINUX_PLATFORM_DEVICE_H__

#include <linux/device.h>

struct platform_device;

static inline void
platform_device_unregister(struct platform_device *pdev)
{

	panic("%s: unimplemented", __func__);
}
	
static inline struct platform_device *
platform_device_register_simple(const char *name, int id,
    void *res, unsigned int num)
{

	panic("%s: unimplemented", __func__);
}

#endif /* __DRMCOMPAT_LINUX_PLATFORM_DEVICE_H__ */
