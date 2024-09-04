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

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mman.h>
#include <sys/priv.h>
#include <sys/rwlock.h>
#include <sys/sglist.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <drm/drmP.h>
#include "../../drm_internal.h"

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
	if (rv == ERESTARTSYS)
		rv = ERESTART;

	dev_relthread(cdev, ref);
	return (rv);

out_release:
	dev_relthread(cdev, ref);
	return (rv);
	return (ENXIO);
}

/*
 * Glue between a VM object, DRM GEM object (referenced via object->handle), and
 * mappings of said VM object.  The FreeBSD VM fault handler gives us very
 * little visibility into the mappings of the object, so this list of vmas is
 * not really used.
 */
struct drm_object_glue {
	vm_object_t		object;
	const struct vm_operations_struct *ops;
	TAILQ_HEAD(, vm_area_struct) vmas;	/* existing mappings */
	TAILQ_ENTRY(drm_object_glue) link;	/* global list linkage */
};

static struct sx drm_vma_lock;
SX_SYSINIT(drm_freebsd, &drm_vma_lock, "drmcompat-vma-lock");
static TAILQ_HEAD(, drm_object_glue) drm_vma_head =
    TAILQ_HEAD_INITIALIZER(drm_vma_head);

static void
drm_vmap_free(struct vm_area_struct *vmap)
{
	kfree(vmap);
}

static int
drm_cdev_pager_fault(vm_object_t vm_obj __unused, vm_ooffset_t offset __unused,
    int prot __unused, vm_page_t *mres __unused)
{
	return (VM_PAGER_FAIL);
}

static int
drm_cdev_pager_populate(vm_object_t vm_obj, vm_pindex_t pidx, int fault_type,
    vm_prot_t max_prot, vm_pindex_t *first, vm_pindex_t *last)
{
	struct vm_fault vmf;
	struct drm_object_glue *dog;
	int err;

	VM_OBJECT_WUNLOCK(vm_obj);

	sx_slock(&drm_vma_lock);
	TAILQ_FOREACH(dog, &drm_vma_head, link) {
		if (dog->object->handle == vm_obj->handle)
			break;
	}
	sx_sunlock(&drm_vma_lock);
	MPASS(dog != NULL);

	if (unlikely(dog->ops == NULL)) {
		err = VM_FAULT_SIGBUS;
	} else {
		vmf.object = vm_obj;
		vmf.pindex = pidx;
		vmf.flags = (fault_type & VM_PROT_WRITE) ? FAULT_FLAG_WRITE : 0;
		vmf.pgoff = 0;
		vmf.page = NULL;
		vmf.count = 0;

		err = dog->ops->fault(&vmf);

		while (vmf.count == 0 && err == VM_FAULT_NOPAGE) {
			kern_yield(PRI_USER);
			err = dog->ops->fault(&vmf);
		}
	}
	VM_OBJECT_WLOCK(vm_obj);

	/* translate return code */
	switch (err) {
	case VM_FAULT_OOM:
		err = VM_PAGER_AGAIN;
		break;
	case VM_FAULT_SIGBUS:
		err = VM_PAGER_FAIL;
		break;
	case VM_FAULT_NOPAGE:
		/*
		 * By contract the fault handler will return having
		 * busied all the pages itself. If pidx is already
		 * found in the object, it will simply xbusy the first
		 * page and return with vm_pfn_count set to 1.
		 */
		*first = vmf.pindex;
		*last = *first + vmf.count - 1;
		err = VM_PAGER_OK;
		break;
	default:
		err = VM_PAGER_ERROR;
		break;
	}
	return (err);
}

static int
drm_cdev_pager_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
		      vm_ooffset_t foff, struct ucred *cred, u_short *color)
{
	*color = 0;
	return (0);
}

static void
drm_cdev_pager_dtor(void *handle)
{
	struct vm_area_struct *vma, *vma1;
	struct drm_object_glue *dog;

	sx_xlock(&drm_vma_lock);
	TAILQ_FOREACH(dog, &drm_vma_head, link) {
		if (dog->object->handle == handle)
			break;
	}
	MPASS(dog != NULL);
	TAILQ_REMOVE(&drm_vma_head, dog, link);
	sx_xunlock(&drm_vma_lock);

	MPASS(!TAILQ_EMPTY(&dog->vmas));
	TAILQ_FOREACH_SAFE(vma, &dog->vmas, vm_entry, vma1) {
		TAILQ_REMOVE(&dog->vmas, vma, vm_entry);
		vma->vm_ops->close(vma);
		drm_vmap_free(vma);
	}
	kfree(dog);
}

static void
drm_phys_pager_dtor(vm_object_t object)
{
	drm_cdev_pager_dtor(object->handle);
}

static const struct phys_pager_ops drm_phys_pg_objs = {
	/* OBJT_PHYS */
	.phys_pg_populate	= drm_cdev_pager_populate,
	.phys_pg_dtor		= drm_phys_pager_dtor
};

static const struct cdev_pager_ops drm_mgtdev_pg_ops = {
	/* OBJT_MGTDEVICE */
	.cdev_pg_populate	= drm_cdev_pager_populate,
	.cdev_pg_ctor		= drm_cdev_pager_ctor,
	.cdev_pg_dtor		= drm_cdev_pager_dtor
};

static const struct cdev_pager_ops drm_dev_pg_ops = {
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
	vmap->vm_pfn_pcount = &vmap->vm_pfn_count;

	rv = fops->mmap(file, vmap);
	if (rv != 0) {
		drm_vmap_free(vmap);
		return (rv);
	}
	attr = pgprot2cachemode(vmap->vm_page_prot);

	if (vmap->vm_ops != NULL) {
		struct drm_object_glue *dog;
		void *handle;

		if (vmap->vm_ops->open == NULL ||
		    vmap->vm_ops->close == NULL ||
		    vmap->vm_private_data == NULL) {
			/* free allocated VM area struct */
			drm_vmap_free(vmap);
			return (EINVAL);
		}

		handle = vmap->vm_private_data;

		sx_xlock(&drm_vma_lock);
		TAILQ_FOREACH(dog, &drm_vma_head, link) {
			if (dog->object->handle == handle)
				break;
		}
		if (dog != NULL) {
			KASSERT(dog->ops == vmap->vm_ops,
			    ("mismatched vm_ops"));
			TAILQ_INSERT_HEAD(&dog->vmas, vmap, vm_entry);
			*obj = dog->object;
			vm_object_reference(*obj);
		} else {
			switch (vmap->vm_ops->objtype) {
			case OBJT_DEVICE:
			case OBJT_MGTDEVICE:
				*obj = cdev_pager_allocate(handle,
				    vmap->vm_ops->objtype,
				    vmap->vm_ops->objtype == OBJT_DEVICE ?
				    &drm_dev_pg_ops : &drm_mgtdev_pg_ops,
				    size, prot, *foff, td->td_ucred);
				break;
			case OBJT_PHYS:
				*obj = phys_pager_allocate(handle,
				    &drm_phys_pg_objs, NULL, size, prot, *foff,
				    td->td_ucred);
				break;
			default:
				__assert_unreachable();
			}
			dog = kzalloc(sizeof(*dog), GFP_KERNEL);
			dog->object = *obj;
			dog->ops = vmap->vm_ops;
			TAILQ_INIT(&dog->vmas);

			TAILQ_INSERT_HEAD(&dog->vmas, vmap, vm_entry);
			TAILQ_INSERT_HEAD(&drm_vma_head, dog, link);
		}
		vmap->vm_obj = dog->object;
		sx_xunlock(&drm_vma_lock);
	} else {
		struct sglist *sg;

		sg = sglist_alloc(1, M_WAITOK);
		sglist_append_phys(sg, (vm_paddr_t)vmap->vm_pfn << PAGE_SHIFT,
		    vmap->vm_len);

		*obj = vm_pager_allocate(OBJT_SG, sg, size, prot, 0,
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
