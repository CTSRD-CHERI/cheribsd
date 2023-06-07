#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/systm.h>
#include <sys/unistd.h>

#include <machine/atomic.h>

#include <linux/sync_file.h>

MALLOC_DEFINE(M_SYNCFILE, "syncfile", "sync file allocator");

static fo_close_t syncfile_fop_close;
static fo_ioctl_t syncfile_fop_ioctl;
static fo_poll_t syncfile_fop_poll;

static int
syncfile_fo_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{

	return (0);
}

static struct fileops syncfile_fileops = {
	.fo_close = syncfile_fop_close,
	.fo_ioctl = syncfile_fop_ioctl,
	.fo_poll = syncfile_fop_poll,
	.fo_flags = DFLAG_PASSABLE,
	.fo_fill_kinfo = syncfile_fo_fill_kinfo,
};

#define	DTYPE_SYNCFILE		101	/* XXX */
#define	file_is_syncfile(file)	((file)->f_ops == &syncfile_fileops)

static struct sync_file 
*sync_file_alloc(void)
{
	struct sync_file *sf;
	int rv;

	sf = malloc(sizeof(struct sync_file), M_SYNCFILE, M_WAITOK | M_ZERO);

	rv = falloc_noinstall(curthread, &sf->sf_file);
	if (rv != 0) {
		free(sf, M_SYNCFILE);
		return (NULL);
	}

	finit(sf->sf_file, O_CLOEXEC, DTYPE_SYNCFILE, sf,
	    &syncfile_fileops);


	return (sf);

}

struct sync_file *
sync_file_create(struct dma_fence *fence)
{
	struct sync_file *sf;

	sf = sync_file_alloc();
	if (sf == NULL)
		return (NULL);

	sf->fence = dma_fence_get(fence);
	return (sf);
}

static struct sync_file *
sync_file_fdget(int fd)
{
	struct file *file;
	cap_rights_t rights;
	int rv;
	
	CAP_ALL(&rights);
	rv = fget(curthread, fd, &rights, &file);
	if (rv != 0)
		return (NULL);

	if (!file_is_syncfile(file)) {
		fdrop(file, curthread);
		return (NULL);
	}

	return (file->f_data);
}

struct dma_fence *
sync_file_get_fence(int fd)
{
	struct sync_file *sf;
	struct dma_fence *fence;
	
	sf = sync_file_fdget(fd);
	if (sf == NULL)
		return (NULL);

	fence = dma_fence_get(sf->fence);
	fdrop(sf->sf_file, curthread);

	return (fence);
}

static int
syncfile_fop_close(struct file *file, struct thread *td)
{
	struct sync_file *sf;

	if (!file_is_syncfile(file))
		return (EINVAL);
	sf = file->f_data;

	if (test_bit(POLL_ENABLED, &sf->flags))
		dma_fence_remove_callback(sf->fence, &sf->cb);
	dma_fence_put(sf->fence);

	free(sf, M_SYNCFILE);
	return (0);
}

static int
syncfile_fop_poll(struct file *file, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct sync_file *sf;

	if (!file_is_syncfile(file))
		return (EINVAL);
	sf = file->f_data;
	panic("Implement %s", __func__);

	return (dma_fence_is_signaled(sf->fence) ? POLLIN : 0);
}

static int
syncfile_fop_ioctl(struct file *file, u_long com, void *data,
	      struct ucred *active_cred, struct thread *td)
{
	if (!file_is_syncfile(file))
		return (EINVAL);
	panic("Implement %s", __func__);

	return (ENOTTY);
}
