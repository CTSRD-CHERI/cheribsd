/*	$NetBSD: linux_dma_buf.c,v 1.4 2018/08/27 15:25:13 riastradh Exp $	*/

/*-
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Taylor R. Campbell.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

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
#include <sys/systm.h>
#include <sys/unistd.h>

#include <machine/atomic.h>

#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/reservation.h>

#include <uapi/linux/dma-buf.h>


MALLOC_DEFINE(M_DMABUF, "dmabuf", "dmabuf allocator");

struct dma_buf_file {
	struct dma_buf	*dbf_dmabuf;
};

static fo_close_t dmabuf_fop_close;
static fo_ioctl_t dmabuf_fop_ioctl;
static fo_kqfilter_t dmabuf_fop_kqfilter;
static fo_mmap_t dmabuf_fop_mmap;
static fo_poll_t dmabuf_fop_poll;
static fo_seek_t dmabuf_fop_seek;

static int
dmabuf_fop_stat(struct file *fp, struct stat *sb, struct ucred *cred)
{

	return (0);
}

static int
dmabuf_fo_fill_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{

        return (0);
}

static struct fileops dmabuf_fileops = {
	.fo_close = dmabuf_fop_close,
	.fo_ioctl = dmabuf_fop_ioctl,
	.fo_kqfilter = dmabuf_fop_kqfilter,
	.fo_mmap = dmabuf_fop_mmap,
	.fo_poll = dmabuf_fop_poll,
	.fo_seek = dmabuf_fop_seek,
	.fo_flags = DFLAG_PASSABLE | DFLAG_SEEKABLE,
	.fo_stat = dmabuf_fop_stat,
	.fo_fill_kinfo = dmabuf_fo_fill_kinfo,
};

#define	DTYPE_DMABUF		100	/* XXX */
#define	file_is_dmabuf(file)	((file)->f_ops == &dmabuf_fileops)

struct dma_buf *
linux_dma_buf_export(struct dma_buf_export_info *info)
{
	struct dma_buf *dmabuf;
	int size, rv;

	if (info->resv == NULL)
		size = offsetof(struct dma_buf, db_resv_int[1]);
	else
		size = sizeof(*dmabuf);

	dmabuf = malloc(size, M_DMABUF, M_WAITOK | M_ZERO);
	dmabuf->priv = info->priv;
	dmabuf->ops = info->ops;
	dmabuf->size = info->size;
	dmabuf->resv = info->resv;

	sx_init(&dmabuf->db_sx, "dma-buf");
	reservation_poll_init(&dmabuf->db_resv_poll);

	if (dmabuf->resv == NULL) {
		dmabuf->resv = &dmabuf->db_resv_int[0];
		reservation_object_init(dmabuf->resv);
	}

	rv = falloc_noinstall(curthread, &dmabuf->db_file);
	if (rv != 0) {
		free(dmabuf, M_DMABUF);
		return (NULL);
	}

	finit(dmabuf->db_file, info->flags & O_CLOEXEC, DTYPE_DMABUF, dmabuf,
	    &dmabuf_fileops);

	return (dmabuf);
}

int
dma_buf_fd(struct dma_buf *dmabuf, int flags)
{
	int fd, rv;

	if (dmabuf == NULL || dmabuf->db_file == NULL)
		return (-EINVAL);

	rv = finstall(curthread, dmabuf->db_file, &fd, flags & O_CLOEXEC, NULL);
	if (rv != 0)
		return (-rv);

	/* drop extra reference added by finstall */
	fdrop(dmabuf->db_file, curthread);

	return (fd);
}

struct dma_buf *
dma_buf_get(int fd)
{
	struct file *file;
	struct dma_buf *dmabuf;
	cap_rights_t rights;
	int rv;

	CAP_ALL(&rights);
	rv = fget(curthread, fd, &rights, &file);
	if (rv != 0)
		return (ERR_PTR(-rv));

	if (!file_is_dmabuf(file)) {
		fdrop(file, curthread);
		return (ERR_PTR(-EINVAL));
	}

	dmabuf = file->f_data;
	return (dmabuf);
}


void
dma_buf_put(struct dma_buf *dmabuf)
{

	MPASS(dmabuf != NULL);
	MPASS(dmabuf->db_file != NULL);

	fdrop(dmabuf->db_file, curthread);
}

void
get_dma_buf(struct dma_buf *dmabuf)
{

	MPASS(dmabuf != NULL);
	MPASS(dmabuf->db_file != NULL);

	while (!fhold(dmabuf->db_file))
		pause("fhold", hz);
}

struct dma_buf_attachment *
dma_buf_attach(struct dma_buf *dmabuf, struct _device *dev)
{
	struct dma_buf_attachment *attach;
	int rv;

	MPASS(dmabuf != NULL);
	MPASS(dev != NULL);

	rv = 0;
	if (dmabuf == NULL || dev == NULL)
		return (ERR_PTR(-EINVAL));

	attach = malloc(sizeof(*attach), M_DMABUF, M_WAITOK | M_ZERO);
	attach->dmabuf = dmabuf;
	attach->dev = dev;

	sx_xlock(&dmabuf->db_sx);
	if (dmabuf->ops->attach != NULL)
		rv = dmabuf->ops->attach(dmabuf, attach);
	sx_xunlock(&dmabuf->db_sx);
	if (rv != 0) {
		free(attach, M_DMABUF);
		return ERR_PTR(rv);
	}

	return (attach);
}

void
dma_buf_detach(struct dma_buf *dmabuf, struct dma_buf_attachment *attach)
{
	MPASS(dmabuf != NULL);
	MPASS(attach != NULL);

	if (dmabuf == NULL || attach == NULL)
		return;

	sx_xlock(&dmabuf->db_sx);
	if (dmabuf->ops->detach)
		dmabuf->ops->detach(dmabuf, attach);
	sx_xunlock(&dmabuf->db_sx);

	free(attach, M_DMABUF);
}

struct sg_table *
dma_buf_map_attachment(struct dma_buf_attachment *attach,
    enum dma_data_direction dir)
{

	MPASS(attach != NULL);
	MPASS(attach->dmabuf != NULL);

	if (attach == NULL || attach->dmabuf == NULL)
		return (ERR_PTR(-EINVAL));

	return (attach->dmabuf->ops->map_dma_buf(attach, dir));
}

void
dma_buf_unmap_attachment(struct dma_buf_attachment *attach,
    struct sg_table *sg, enum dma_data_direction dir)
{

	MPASS(attach != NULL);
	MPASS(attach->dmabuf != NULL);

	if (attach == NULL || attach->dmabuf == NULL)
		return;

	return (attach->dmabuf->ops->unmap_dma_buf(attach, sg, dir));
}

static int
dmabuf_fop_close(struct file *file, struct thread *td)
{
	struct dma_buf *dmabuf;

	if (!file_is_dmabuf(file))
		return (EINVAL);

	dmabuf = file->f_data;

	dmabuf->ops->release(dmabuf);
	reservation_poll_fini(&dmabuf->db_resv_poll);

	if (dmabuf->resv == &dmabuf->db_resv_int[0])
		reservation_object_fini(dmabuf->resv);

	sx_destroy(&dmabuf->db_sx);
	free(dmabuf, M_DMABUF);
	return (0);
}

static int
dmabuf_fop_poll(struct file *file, int events, struct ucred *active_cred,
    struct thread *td)
{
	struct dma_buf *dmabuf;
	struct reservation_poll *rpoll;

	if (!file_is_dmabuf(file))
		return (EINVAL);

	dmabuf = file->f_data;

	rpoll = &dmabuf->db_resv_poll;

	return (reservation_object_poll(dmabuf->resv, events, rpoll));
}

static int
dmabuf_fop_kqfilter(struct file *file, struct knote *kn)
{
	struct dma_buf *dmabuf;
	struct reservation_poll *rpoll;

	if (!file_is_dmabuf(file))
		return (EINVAL);

	dmabuf = file->f_data;

	rpoll = &dmabuf->db_resv_poll;

	return (reservation_object_kqfilter(dmabuf->resv, kn, rpoll));
}

static int
dmabuf_fop_mmap(struct file *file, vm_map_t map, vm_pointer_t *addr,
	    vm_offset_t max_addr, vm_size_t size, vm_prot_t prot,
	    vm_prot_t cap_maxprot, int flags, vm_ooffset_t foff,
	    struct thread *td)
{
	struct dma_buf *dmabuf;
	struct vm_area_struct vma;

	if (!file_is_dmabuf(file))
		return (EINVAL);

	dmabuf = file->f_data;

	if (foff + size  > dmabuf->size)
		return (EINVAL);

	if (*addr + size > max_addr)
		return (EINVAL);

	vma.vm_start = *addr;
	vma.vm_end = *addr + size;
	vma.vm_pgoff = foff;

	return (-dmabuf->ops->mmap(dmabuf, &vma));
}

static int
dmabuf_fop_seek(struct file *file, off_t offset, int whence, struct thread *td)
{
	struct dma_buf *dmabuf;
	off_t base;

	if (!file_is_dmabuf(file))
		return (EINVAL);

	dmabuf = file->f_data;

	if (offset != 0)
		return (EINVAL);

	if (whence == SEEK_END)
		base = dmabuf->size;
	else if (whence == SEEK_SET)
		base = 0;
	else
		return (EINVAL);

	td->td_retval[0] = file->f_offset = base;
	return (0);
}

static int
dmabuf_fop_ioctl(struct file *file, u_long com, void *data,
	      struct ucred *active_cred, struct thread *td)
{
	struct dma_buf *dmabuf;
	struct dma_buf_sync *sync;
	enum dma_data_direction dir;
	int rv;

	if (!file_is_dmabuf(file))
		return (EINVAL);

	dmabuf = file->f_data;

	sync = data;
	rv = 0;

	switch (com) {
	case DMA_BUF_IOCTL_SYNC:
		if (sync->flags & ~DMA_BUF_SYNC_VALID_FLAGS_MASK)
			return (EINVAL);

		switch (sync->flags & DMA_BUF_SYNC_RW) {
		case DMA_BUF_SYNC_READ:
			dir = DMA_FROM_DEVICE;
			break;
		case DMA_BUF_SYNC_WRITE:
			dir = DMA_TO_DEVICE;
			break;
		case DMA_BUF_SYNC_RW:
			dir = DMA_BIDIRECTIONAL;
			break;
		default:
			return (EINVAL);
		}
		rv = 0;
		if (sync->flags & DMA_BUF_SYNC_END) {
			if (dmabuf->ops->end_cpu_access != NULL)
				rv = dmabuf->ops->end_cpu_access(dmabuf, dir);
		} else {
			if (dmabuf->ops->begin_cpu_access != NULL)
				rv = dmabuf->ops->begin_cpu_access(dmabuf, dir);
		}
		return (-rv);
	default:
		return (ENOTTY);
	}
}
