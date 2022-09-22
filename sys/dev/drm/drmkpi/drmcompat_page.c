/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2016 Matthew Macy (mmacy@mattmacy.io)
 * Copyright (c) 2017 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/rwlock.h>
#include <sys/proc.h>

#include <machine/bus.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_radix.h>
#include <vm/vm_reserv.h>
#include <vm/vm_extern.h>

#include <linux/err.h>	/* For ERR_PTR */
#include <linux/gfp.h>
#include <linux/slab.h>	/* For kzalloc */

#include <drmcompat/fs.h>

vm_pointer_t
drmcompat_alloc_kmem(gfp_t flags, unsigned int order)
{
	size_t size = ((size_t)PAGE_SIZE) << order;
	void *addr;

	if ((flags & GFP_DMA32) == 0) {
		addr = kmem_malloc(size, flags & GFP_NATIVE_MASK);
	} else {
		addr = kmem_alloc_contig(size, flags & GFP_NATIVE_MASK, 0,
		    BUS_SPACE_MAXADDR_32BIT, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	}
	return ((vm_pointer_t)addr);
}

void
drmcompat_free_kmem(vm_pointer_t addr, unsigned int order)
{
	size_t size = ((size_t)PAGE_SIZE) << order;

	kmem_free((void *)addr, size);
}

struct file *
drmcompat_shmem_file_setup(const char *name, loff_t size, unsigned long flags)
{
	struct fileobj {
		struct file file __aligned(sizeof(void *));
		struct vnode vnode __aligned(sizeof(void *));
	};
	struct fileobj *fileobj;
	struct file *filp;
	struct vnode *vp;
	int error;
	vm_object_t obj;

	fileobj = kzalloc(sizeof(*fileobj), GFP_KERNEL);
	if (fileobj == NULL) {
		error = -ENOMEM;
		goto err_0;
	}
	filp = &fileobj->file;
	vp = &fileobj->vnode;

	filp->f_count = 1;
	filp->f_vnode = vp;
	obj = vm_pager_allocate(OBJT_DEFAULT, NULL, size,
	    VM_PROT_READ | VM_PROT_WRITE, 0, curthread->td_ucred);
	if (obj == NULL) {
		error = -ENOMEM;
		goto err_1;
	}
	return (filp);
err_1:
	kfree(filp);
err_0:
	return (ERR_PTR(error));
}
