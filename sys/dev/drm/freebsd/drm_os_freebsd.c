/*-
 * Copyright (c) 2015 Jean-Sébastien Pédron <dumbbell@FreeBSD.org>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/priv.h>
#include <sys/sglist.h>
#include <sys/rwlock.h>
#include <sys/mman.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <drm/drmP.h>
#include "../..//drm_internal.h"

MALLOC_DEFINE(DRM_MEM_DRIVER, "drm_driver", "DRM DRIVER Data Structures");
MALLOC_DEFINE(DRM_MEM_KMS, "drm_kms", "DRM KMS Data Structures");

SYSCTL_NODE(_dev, OID_AUTO, drm, CTLFLAG_RW, 0, "DRM args");

#define	LINUX_POLL_TABLE_NORMAL ((struct poll_table_struct *)1)

static int
drm_fstub_file_check(struct file *file, struct cdev **cdev, int *ref,
    struct drm_minor **minor)
{
	struct cdevsw *cdevsw;

	cdevsw = devvn_refthread(file->f_vnode, cdev, ref);
	if (cdevsw == NULL)
		return (ENXIO);
	KASSERT((*cdev)->si_refcount > 0,
	    ("drm_fstub: un-referenced struct cdev *(%s)", devtoname(*cdev)));
	KASSERT((*cdev)->si_drv1 != NULL,
	    ("drm_fstub: invalid si_drv1 field (%s)", devtoname(*cdev)));
	*minor = (*cdev)->si_drv1;

	return (0);
}

static int
drm_fstub_read(struct file *file, struct uio *uio, struct ucred *cred,
    int flags, struct thread *td)
{
	struct cdev *cdev;
	struct drm_minor *minor;
	const struct file_operations *fops;
	ssize_t bytes;
	int ref, rv;

	/* XXX no support for I/O vectors currently */
	if (uio->uio_iovcnt != 1)
		return (EOPNOTSUPP);
	if (uio->uio_resid > DEVFS_IOSIZE_MAX)
		return (EINVAL);

	rv = drm_fstub_file_check(file, &cdev, &ref, &minor);
	if (rv != 0)
		return (ENXIO);

	fops = minor->dev->driver->fops;
	if (fops == NULL || fops->read == NULL) {
		rv = ENXIO;
		goto out_release;
	}

	foffset_lock_uio(file, uio, flags | FOF_NOLOCK);
	bytes = fops->read(file, uio->uio_iov->iov_base, uio->uio_iov->iov_len,
	   &uio->uio_offset);
	if (rv >= 0) {
		uio->uio_iov->iov_base =
		    ((uint8_t * __capability)uio->uio_iov->iov_base) + bytes;
		uio->uio_iov->iov_len -= bytes;
		uio->uio_resid -= bytes;
		rv = 0;
	} else {
		rv = -bytes;
	}
	foffset_unlock_uio(file, uio, flags | FOF_NOLOCK | FOF_NEXTOFF_R);
	dev_relthread(cdev, ref);
	return (rv);

out_release:
	dev_relthread(cdev, ref);
	return (rv);
}

static int
drm_fstub_write(struct file *file, struct uio *uio, struct ucred *cred,
    int flags, struct thread *td)
{
	struct cdev *cdev;
	struct drm_minor *minor;
	const struct file_operations *fops;
	ssize_t bytes;
	int ref, rv;

	/* XXX no support for I/O vectors currently */
	if (uio->uio_iovcnt != 1)
		return (EOPNOTSUPP);
	if (uio->uio_resid > DEVFS_IOSIZE_MAX)
		return (EINVAL);

	rv = drm_fstub_file_check(file, &cdev, &ref, &minor);
	if (rv != 0)
		return (ENXIO);

	fops = minor->dev->driver->fops;
	if (fops == NULL || fops->write == NULL) {
		rv = ENXIO;
		goto out_release;
	}

	foffset_lock_uio(file, uio, flags | FOF_NOLOCK);
	bytes = fops->write(file, uio->uio_iov->iov_base, uio->uio_iov->iov_len,
	   &uio->uio_offset);
	if (rv >= 0) {
		uio->uio_iov->iov_base =
		    ((uint8_t * __capability)uio->uio_iov->iov_base) + bytes;
		uio->uio_iov->iov_len -= bytes;
		uio->uio_resid -= bytes;
		rv = 0;
	} else {
		rv = -bytes;
	}
	foffset_unlock_uio(file, uio, flags | FOF_NOLOCK | FOF_NEXTOFF_W);
	dev_relthread(cdev, ref);
	return (rv);

out_release:
	dev_relthread(cdev, ref);
	return (rv);
}

static int
drm_fstub_kqfilter(struct file *file, struct knote *kn)
{
	const struct file_operations *fops;
	struct drm_minor *minor;
	struct cdev *cdev;
	int ref;
	int rv;

	rv = drm_fstub_file_check(file, &cdev, &ref, &minor);
	if (rv != 0)
		return (ENXIO);

	fops = minor->dev->driver->fops;
	if (fops->kqfilter != NULL) {
		rv = fops->kqfilter(file, kn);
		return (rv);
	}

	return (EINVAL);
}

static int
drm_fstub_stat(struct file *fp, struct stat *sb, struct ucred *cred)
{

	return (vnops.fo_stat(fp, sb, cred));
}

static int
drm_fstub_poll(struct file *file, int events, struct ucred *cred,
    struct thread *td)
{
	struct cdev *cdev;
	struct drm_minor *minor;
	const struct file_operations *fops;
	int ref, rv;

	if ((events & (POLLIN | POLLRDNORM)) == 0)
		return (0);

	rv = drm_fstub_file_check(file, &cdev, &ref, &minor);
	if (rv != 0)
		return (0);

	fops = minor->dev->driver->fops;
	if (fops == NULL) {
		rv = 0;
		goto out_release;
	}
	if (fops->poll != NULL) {
		rv = fops->poll(file, LINUX_POLL_TABLE_NORMAL);
		rv &= events;
	} else {
		rv = 0;
	}

out_release:
	dev_relthread(cdev, ref);
	return (rv);
}

static int
drm_fstub_close(struct file *file, struct thread *td)
{
	struct cdev *cdev;
	struct drm_minor *minor;
	const struct file_operations *fops;
	int ref, rv;

	rv = drm_fstub_file_check(file, &cdev, &ref, &minor);
	if (rv != 0)
		return (ENXIO);

	fops = minor->dev->driver->fops;
	if (fops == NULL || fops->release == NULL) {
		rv = ENXIO;
		goto out_release;
	}

	rv = fops->release((struct inode*)file->f_vnode, file);
	vdrop(file->f_vnode);

out_release:
	dev_relthread(cdev, ref);
	return (rv);
}

static int
drm_fstub_ioctl(struct file *file, u_long cmd, void *data, struct ucred *cred,
    struct thread *td)
{

	struct cdev *cdev;
	struct drm_minor *minor;
	const struct file_operations *fops;
	int ref, rv;

	rv = drm_fstub_file_check(file, &cdev, &ref, &minor);
	if (rv != 0)
		return (ENXIO);

	fops = minor->dev->driver->fops;
	if (fops == NULL || fops->unlocked_ioctl == NULL) {
		rv = ENOTTY;
		goto out_release;
	}

	rv = -fops->unlocked_ioctl(file, cmd, (uintcap_t)PTR2CAP(data));

	dev_relthread(cdev, ref);
	return (rv);

out_release:
	dev_relthread(cdev, ref);
	return (rv);
	return (ENXIO);
}

static struct rwlock drm_vma_lock;
static TAILQ_HEAD(, vm_area_struct) drm_vma_head =
    TAILQ_HEAD_INITIALIZER(drm_vma_head);

static void
drm_vmap_free(struct vm_area_struct *vmap)
{

	/* Drop reference on mm_struct */
//	mmput(vmap->vm_mm);

	kfree(vmap);
}

static void
drm_vmap_remove(struct vm_area_struct *vmap)
{
	rw_wlock(&drm_vma_lock);
	TAILQ_REMOVE(&drm_vma_head, vmap, vm_entry);
	rw_wunlock(&drm_vma_lock);
}

static struct vm_area_struct *
drm_vmap_find(void *handle)
{
	struct vm_area_struct *vmap;

	rw_rlock(&drm_vma_lock);
	TAILQ_FOREACH(vmap, &drm_vma_head, vm_entry) {
		if (vmap->vm_private_data == handle)
			break;
	}
	rw_runlock(&drm_vma_lock);
	return (vmap);
}

static int
drm_cdev_pager_fault(vm_object_t vm_obj, vm_ooffset_t offset, int prot,
    vm_page_t *mres)
{
	struct vm_area_struct *vmap;

	vmap = drm_vmap_find(vm_obj->handle);

	MPASS(vmap != NULL);
	MPASS(vmap->vm_private_data == vm_obj->handle);

	if (likely(vmap->vm_ops != NULL && offset < vmap->vm_len)) {
		vm_paddr_t paddr = IDX_TO_OFF(vmap->vm_pfn) + offset;
		vm_page_t page;

		if (((*mres)->flags & PG_FICTITIOUS) != 0) {
			/*
			 * If the passed in result page is a fake
			 * page, update it with the new physical
			 * address.
			 */
			page = *mres;
			vm_page_updatefake(page, paddr, vm_obj->memattr);
		} else {
			/*
			 * Replace the passed in "mres" page with our
			 * own fake page and free up the all of the
			 * original pages.
			 */
			VM_OBJECT_WUNLOCK(vm_obj);
			page = vm_page_getfake(paddr, vm_obj->memattr);
			VM_OBJECT_WLOCK(vm_obj);

			vm_page_replace(page, vm_obj,
			    (*mres)->pindex, *mres);

			*mres = page;
		}
		page->valid = VM_PAGE_BITS_ALL;
		return (VM_PAGER_OK);
	}
	return (VM_PAGER_FAIL);
}

static int
drm_cdev_pager_populate(vm_object_t vm_obj, vm_pindex_t pidx, int fault_type,
    vm_prot_t max_prot, vm_pindex_t *first, vm_pindex_t *last)
{
	struct vm_area_struct *vmap;
	int err;


	/* get VM area structure */
	vmap = drm_vmap_find(vm_obj->handle);
	MPASS(vmap != NULL);
	MPASS(vmap->vm_private_data == vm_obj->handle);

	VM_OBJECT_WUNLOCK(vm_obj);

//	down_write(&vmap->vm_mm->mmap_sem);
	if (unlikely(vmap->vm_ops == NULL)) {
		err = VM_FAULT_SIGBUS;
	} else {
		struct vm_fault vmf;

		/* fill out VM fault structure */
		vmf.virtual_address = (void *)(uintptr_t)IDX_TO_OFF(pidx);
		vmf.flags = (fault_type & VM_PROT_WRITE) ? FAULT_FLAG_WRITE : 0;
		vmf.pgoff = 0;
		vmf.page = NULL;
		vmf.vma = vmap;

		vmap->vm_pfn_count = 0;
		vmap->vm_pfn_pcount = &vmap->vm_pfn_count;
		vmap->vm_obj = vm_obj;

		err = vmap->vm_ops->fault(vmap, &vmf);

		while (vmap->vm_pfn_count == 0 && err == VM_FAULT_NOPAGE) {
			kern_yield(PRI_USER);
			err = vmap->vm_ops->fault(vmap, &vmf);
		}
	}

	/* translate return code */
	switch (err) {
	case VM_FAULT_OOM:
		err = VM_PAGER_AGAIN;
		break;
	case VM_FAULT_SIGBUS:
		err = VM_PAGER_BAD;
		break;
	case VM_FAULT_NOPAGE:
		/*
		 * By contract the fault handler will return having
		 * busied all the pages itself. If pidx is already
		 * found in the object, it will simply xbusy the first
		 * page and return with vm_pfn_count set to 1.
		 */
		*first = vmap->vm_pfn_first;
		*last = *first + vmap->vm_pfn_count - 1;
		err = VM_PAGER_OK;
		break;
	default:
		err = VM_PAGER_ERROR;
		break;
	}
//	up_write(&vmap->vm_mm->mmap_sem);
	VM_OBJECT_WLOCK(vm_obj);
	return (err);
}

static int
drm_cdev_pager_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
		      vm_ooffset_t foff, struct ucred *cred, u_short *color)
{

	MPASS(drm_vmap_find(handle) != NULL);
	*color = 0;
	return (0);
}

static void
drm_cdev_pager_dtor(void *handle)
{
	const struct vm_operations_struct *vm_ops;
	struct vm_area_struct *vmap;

	vmap = drm_vmap_find(handle);
	MPASS(vmap != NULL);

	/*
	 * Remove handle before calling close operation to prevent
	 * other threads from reusing the handle pointer.
	 */
	drm_vmap_remove(vmap);

//	down_write(&vmap->vm_mm->mmap_sem);
	vm_ops = vmap->vm_ops;
	if (likely(vm_ops != NULL))
		vm_ops->close(vmap);
//	up_write(&vmap->vm_mm->mmap_sem);

	drm_vmap_free(vmap);
}

static struct cdev_pager_ops drm_mgtdev_pg_ops = {
	/* OBJT_MGTDEVICE */
	.cdev_pg_populate	= drm_cdev_pager_populate,
	.cdev_pg_ctor		= drm_cdev_pager_ctor,
	.cdev_pg_dtor		= drm_cdev_pager_dtor
};

static struct cdev_pager_ops drm_dev_pg_ops = {
	/* OBJT_DEVICE */
	.cdev_pg_fault		= drm_cdev_pager_fault,
	.cdev_pg_ctor		= drm_cdev_pager_ctor,
	.cdev_pg_dtor		= drm_cdev_pager_dtor
};

static int
drm_fstub_do_mmap(struct file *file, const struct file_operations *fops,
    vm_ooffset_t *foff, vm_size_t size, struct vm_object **obj, vm_prot_t prot,
    struct thread *td)
{
	struct vm_area_struct *vmap;
	vm_memattr_t attr;
	int rv;

	vmap = kzalloc(sizeof(*vmap), GFP_KERNEL);
	vmap->vm_start = 0;
	vmap->vm_end = size;
	vmap->vm_pgoff = *foff / PAGE_SIZE;
	vmap->vm_pfn = 0;
	vmap->vm_flags = vmap->vm_page_prot = (prot & VM_PROT_ALL);
	vmap->vm_ops = NULL;
	vmap->vm_file = file;
//	vmap->vm_mm = mm;

	rv = fops->mmap(file, vmap);
//	if (unlikely(down_write_killable(&vmap->vm_mm->mmap_sem))) {
//		rv = EINTR;
//	} else {
//		rv = -fops->mmap(file, vmap);
//		up_write(&vmap->vm_mm->mmap_sem);
//	}
	if (rv != 0) {
		drm_vmap_free(vmap);
		return (rv);
	}
	attr = pgprot2cachemode(vmap->vm_page_prot);

	if (vmap->vm_ops != NULL) {
		struct vm_area_struct *ptr;
		void *vm_private_data;
		bool vm_no_fault;

		if (vmap->vm_ops->open == NULL ||
		    vmap->vm_ops->close == NULL ||
		    vmap->vm_private_data == NULL) {
			/* free allocated VM area struct */
			drm_vmap_free(vmap);
			return (EINVAL);
		}

		vm_private_data = vmap->vm_private_data;

		rw_wlock(&drm_vma_lock);
		TAILQ_FOREACH(ptr, &drm_vma_head, vm_entry) {
			if (ptr->vm_private_data == vm_private_data)
				break;
		}
		/* check if there is an existing VM area struct */
		if (ptr != NULL) {
			/* check if the VM area structure is invalid */
			if (ptr->vm_ops == NULL ||
			    ptr->vm_ops->open == NULL ||
			    ptr->vm_ops->close == NULL) {
				rv = ESTALE;
				vm_no_fault = 1;
			} else {
				rv = EEXIST;
				vm_no_fault = (ptr->vm_ops->fault == NULL);
			}
		} else {
			/* insert VM area structure into list */
			TAILQ_INSERT_TAIL(&drm_vma_head, vmap, vm_entry);
			rv = 0;
			vm_no_fault = (vmap->vm_ops->fault == NULL);
		}
		rw_wunlock(&drm_vma_lock);

		if (rv != 0) {
			/* free allocated VM area struct */
			drm_vmap_free(vmap);
			/* check for stale VM area struct */
			if (rv != EEXIST)
				return (rv);
		}

		/* check if there is no fault handler */
		if (vm_no_fault) {
			*obj = cdev_pager_allocate(vm_private_data,
			    OBJT_DEVICE, &drm_dev_pg_ops, size, prot,
			    *foff, td->td_ucred);
		} else {
			*obj = cdev_pager_allocate(vm_private_data,
			    OBJT_MGTDEVICE, &drm_mgtdev_pg_ops, size, prot,
			    *foff, td->td_ucred);
		}

		/* check if allocating the VM object failed */
		if (*obj == NULL) {
			if (rv == 0) {
				/* remove VM area struct from list */
				drm_vmap_remove(vmap);
				/* free allocated VM area struct */
				drm_vmap_free(vmap);
			}
			return (EINVAL);
		}
	} else {
		struct sglist *sg;

		sg = sglist_alloc(1, M_WAITOK);
		sglist_append_phys(sg, (vm_paddr_t)vmap->vm_pfn << PAGE_SHIFT,
		    vmap->vm_len);

		*obj = vm_pager_allocate(OBJT_SG, sg, vmap->vm_len, prot, 0,
		    td->td_ucred);

		drm_vmap_free(vmap);
		if (*obj == NULL) {
			sglist_free(sg);
			return (EINVAL);
		}
	}

	if (attr != VM_MEMATTR_DEFAULT) {
		VM_OBJECT_WLOCK(*obj);
		vm_object_set_memattr(*obj, attr);
		VM_OBJECT_WUNLOCK(*obj);
	}
	*foff = 0;
	return (0);
}

static int
drm_fstub_mmap(struct file *file, vm_map_t map, vm_pointer_t *addr,
    vm_offset_t max_addr, vm_size_t size, vm_prot_t prot,
    vm_prot_t cap_maxprot, int flags, vm_ooffset_t foff, struct thread *td)
{
	struct cdev *cdev;
	struct drm_minor *minor;
	const struct file_operations *fops;
	struct vm_object *obj;
	struct vnode *vp;
	struct mount *mp;
	vm_prot_t maxprot;
	int ref, rv;

	vp = file->f_vnode;
	if (vp == NULL)
		return (EOPNOTSUPP);

	/*
	 * Ensure that file and memory protections are
	 * compatible.
	 */
	mp = vp->v_mount;
	if (mp != NULL && (mp->mnt_flag & MNT_NOEXEC) != 0) {
		maxprot = VM_PROT_NONE;
		if ((prot & VM_PROT_EXECUTE) != 0)
			return (EACCES);
	} else
		maxprot = VM_PROT_EXECUTE;
	if ((file->f_flag & FREAD) != 0)
		maxprot |= VM_PROT_READ;
	else if ((prot & VM_PROT_READ) != 0)
		return (EACCES);

	/*
	 * If we are sharing potential changes via MAP_SHARED and we
	 * are trying to get write permission although we opened it
	 * without asking for it, bail out.
	 */
	if ((flags & MAP_SHARED) != 0) {
		if ((file->f_flag & FWRITE) != 0)
			maxprot |= VM_PROT_WRITE;
		else if ((prot & VM_PROT_WRITE) != 0)
			return (EACCES);
	}
	maxprot &= cap_maxprot;
	/*
	 * Character devices do not provide private mappings
	 * of any kind:
	 */
	if ((maxprot & VM_PROT_WRITE) == 0 &&
	    (prot & VM_PROT_WRITE) != 0)
		return (EACCES);
	if ((flags & (MAP_PRIVATE | MAP_COPY)) != 0)
		return (EINVAL);

	rv = drm_fstub_file_check(file, &cdev, &ref, &minor);
	if (rv != 0)
		return (ENXIO);

	fops = minor->dev->driver->fops;
	if (fops == NULL || fops->mmap == NULL) {
		rv = ENXIO;
		goto out_release;
	}

	rv = drm_fstub_do_mmap(file, fops, &foff, size, &obj, prot, td);
	if (rv != 0)
		goto out_release;

	rv = vm_mmap_object(map, addr, max_addr, size, prot, maxprot, flags,
	    obj, foff, FALSE, td);
	if (rv != 0)
		vm_object_deallocate(obj);
out_release:
	dev_relthread(cdev, ref);
	return (rv);
}

static struct fileops drmfileops = {
	.fo_read = drm_fstub_read,
	.fo_write = drm_fstub_write,
	.fo_truncate = invfo_truncate,
	.fo_kqfilter = drm_fstub_kqfilter,
	.fo_stat = drm_fstub_stat,
	.fo_fill_kinfo = vn_fill_kinfo,
	.fo_poll = drm_fstub_poll,
	.fo_close = drm_fstub_close,
	.fo_ioctl = drm_fstub_ioctl,
	.fo_mmap = drm_fstub_mmap,
	.fo_chmod = invfo_chmod,
	.fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile,
	.fo_flags = DFLAG_PASSABLE,
};

static int
drm_cdev_fdopen(struct cdev *cdev, int fflags, struct thread *td,
    struct file *file)
{
	struct drm_minor *minor;
	const struct file_operations *fops;
	int rv;

	/* Keep in sync with drm_stub_open*/
	DRM_DEBUG("\n");

	mutex_lock(&drm_global_mutex);
	minor = drm_minor_acquire(cdev->si_drv0);
	if (IS_ERR(minor)) {
		rv = PTR_ERR(minor);
		goto out_unlock;
	}

	fops = minor->dev->driver->fops;
	if (fops == NULL) {
		rv = -ENODEV;
		goto out_release;
	}

	/* hold on to the vnode - used for fstat() */
	vhold(file->f_vnode);
	/* release the file from devfs */
	finit(file, file->f_flag, DTYPE_DEV, NULL, &drmfileops);

	rv = 0;
	if (fops->open)
		rv = fops->open((struct inode*)file->f_vnode, file);
	if (rv != 0)
		vdrop(file->f_vnode);

out_release:
	drm_minor_release(minor);
out_unlock:
	mutex_unlock(&drm_global_mutex);
	return -rv;
}

static struct cdevsw drm_cdevsw = {
	.d_version =	D_VERSION,
	.d_fdopen = 	drm_cdev_fdopen,
	.d_name =	"drm",
};

int
drm_fbsd_cdev_create(struct drm_minor *minor)
{
	const char *minor_devname;
	struct make_dev_args args;
	int rv;

	switch (minor->type) {
	case DRM_MINOR_CONTROL:
		minor_devname = "dri/controlD%d";
		break;
	case DRM_MINOR_RENDER:
		minor_devname = "dri/renderD%d";
		break;
	default:
		minor_devname = "dri/card%d";
		break;
	}

	/* Setup arguments for make_dev_s() */
	make_dev_args_init(&args);
	args.mda_devsw = &drm_cdevsw;
	args.mda_uid = DRM_DEV_UID;
	args.mda_gid = DRM_DEV_GID;
	args.mda_mode = DRM_DEV_MODE;
	args.mda_unit = minor->index;
	args.mda_si_drv1 = minor;

	rv = make_dev_s(&args, &minor->kdev, minor_devname, minor->index);
	if (rv != 0)
		return (-rv);
	DRM_DEBUG("new device created %s%d\n", minor_devname, minor->index);
	return 0;
}

void drm_fbsd_cdev_delete(struct drm_minor *minor)
{

	destroy_dev(minor->kdev);
}

int drm_legacy_irq_control(struct drm_device *dev, void *data,
			   struct drm_file *file_priv)
{
	panic("%s: Not implemented yet.", __func__);
}

int drm_irq_uninstall(struct drm_device *dev)
{
	panic("%s: Not implemented yet.", __func__);
}

static void
drm_stub_init(void *arg)
{
	rw_init(&drm_vma_lock, "drmcompat-vma-lock");
}

static void
drm_stub_uninit(void *arg)
{
	rw_destroy(&drm_vma_lock);
}

SYSINIT(drm_stub, SI_SUB_DRIVERS, SI_ORDER_SECOND, drm_stub_init, NULL);
SYSUNINIT(drm_stub, SI_SUB_DRIVERS, SI_ORDER_SECOND, drm_stub_uninit, NULL);
