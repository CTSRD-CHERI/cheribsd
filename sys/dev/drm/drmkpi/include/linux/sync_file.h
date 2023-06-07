#ifndef __DRMCOMPAT_LINUX_SYNC_FILE_H__
#define __DRMCOMPAT_LINUX_SYNC_FILE_H__

#include <sys/types.h>
#include <sys/mutex.h>

#include <linux/dma-fence.h>

struct sync_file {
	char			user_name[32];
//	wait_queue_head_t	wq;
	unsigned long		flags;
	struct dma_fence	*fence;
	struct dma_fence_cb	cb;

	struct file		*sf_file;
};

#define POLL_ENABLED 0

struct sync_file *sync_file_create(struct dma_fence *fence);
struct dma_fence *sync_file_get_fence(int fd);
char *sync_file_get_name(struct sync_file *sync_file, char *buf, int len);

#endif /* __DRMCOMPAT_LINUX_SYNC_H__ */
