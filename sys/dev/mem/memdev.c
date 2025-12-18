/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2004 Mark R V Murray
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/memrange.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#if __has_feature(capabilities)
#include <vm/vm_extern.h>
#endif
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>

#include <machine/memdev.h>

#ifdef COMPAT_FREEBSD64
struct mem_cheri_cap_arg64 {
	uint64_t	vaddr;
	uint64_t	buf;
	size_t		len;
};

#define	MEM_READ_CHERI_CAP64	_IOW('m', 100, struct mem_cheri_cap_arg64)
#endif

static struct cdev *memdev, *kmemdev;

static d_ioctl_t memioctl;

static struct cdevsw mem_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	D_MEM,
	.d_open =	memopen,
	.d_read =	memrw,
	.d_write =	memrw,
	.d_ioctl =	memioctl,
	.d_mmap =	memmmap,
	.d_name =	"mem",
};

/* ARGSUSED */
int
memopen(struct cdev *dev __unused, int flags, int fmt __unused,
    struct thread *td)
{
	int error = 0;

	if (flags & FREAD)
		error = priv_check(td, PRIV_KMEM_READ);
	if (flags & FWRITE) {
		if (error == 0)
			error = priv_check(td, PRIV_KMEM_WRITE);
		if (error == 0)
			error = securelevel_gt(td->td_ucred, 0);
	}

	return (error);
}

#if __has_feature(capabilities)
/*
 * Helper for MEM_READ_CHERI_CAP that copies out capabilities one at a
 * time.  len is the "expanded" length (extra tag byte for each
 * capability stride).
 */
static int
mem_read_cheri_caps(struct cdev *dev, const struct mem_cheri_cap_arg *arg)
{
	char capbuf[sizeof(uintcap_t) + 1];
	struct vm_page m;
	vm_page_t marr[1];
	uintcap_t * __capability dst;
	const uintcap_t *src;
	vm_paddr_t pa;
	vm_pointer_t mapped_ptr;
	ptraddr_t va;
	size_t len;
	u_int page_off, todo;
	int error;
	bool mapped;

	if (!is_aligned(arg->vaddr, sizeof(uintcap_t)))
		return (EINVAL);
	if (arg->len == 0 || arg->len % (sizeof(uintcap_t) + 1) != 0)
		return (EINVAL);

	va = arg->vaddr;
	dst = arg->buf;
	len = arg->len / (sizeof(uintcap_t) + 1) * sizeof(uintcap_t);
	error = 0;
	while (len != 0 && error == 0) {
		page_off = va & PAGE_MASK;
		todo = PAGE_SIZE - page_off;
		if (todo > len)
			todo = len;

		/* Get the physical address to read */
		switch (dev2unit(dev)) {
		case CDEV_MINOR_KMEM:
			if (VIRT_IN_DMAP(va)) {
				pa = DMAP_TO_PHYS(va);
				break;
			}

			if (!kernacc((void *)(uintptr_t)va, todo, VM_PROT_READ))
				return (EFAULT);

			pa = pmap_extract(kernel_pmap, va);
			if (pa == 0)
				return (EFAULT);
			break;
		case CDEV_MINOR_MEM:
			pa = va;
			break;
		default:
			__assert_unreachable();
		}

		m.phys_addr = trunc_page(pa);
		marr[0] = &m;
		mapped = pmap_map_io_transient(marr, &mapped_ptr, 1, TRUE);

		va += todo;
		len -= todo;

		src = (uintcap_t *)((char *)mapped_ptr + page_off);
		while (todo != 0) {
			capbuf[0] = cheri_gettag(*src);
			memcpy(capbuf + 1, src, sizeof(*src));

			error = copyout(capbuf, dst, sizeof(capbuf));
			if (error != 0)
				break;

			src++;
			dst++;
			todo -= sizeof(uintcap_t);
		}

		if (__predict_false(mapped))
			pmap_unmap_io_transient(marr, &mapped_ptr, 1, TRUE);
	}

	return (error);
}
#endif

static int
memioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{
	vm_map_t map;
	vm_map_entry_t entry;
#if __has_feature(capabilities)
	const struct mem_cheri_cap_arg *cap_arg;
#ifdef COMPAT_FREEBSD64
	struct mem_cheri_cap_arg cap_arg_thunk;
	const struct mem_cheri_cap_arg64 *cap_arg64;
#endif
#endif
	const struct mem_livedump_arg *marg;
	struct mem_extract *me;
	int error;

	error = 0;
	switch (cmd) {
	case MEM_EXTRACT_PADDR:
		me = (struct mem_extract *)data;

		map = &td->td_proc->p_vmspace->vm_map;
		vm_map_lock_read(map);
		if (vm_map_lookup_entry(map, me->me_vaddr, &entry)) {
			me->me_paddr = pmap_extract(
			    &td->td_proc->p_vmspace->vm_pmap, me->me_vaddr);
			if (me->me_paddr != 0) {
				me->me_state = ME_STATE_MAPPED;
				me->me_domain = vm_phys_domain(me->me_paddr);
			} else {
				me->me_state = ME_STATE_VALID;
			}
		} else {
			me->me_state = ME_STATE_INVALID;
		}
		vm_map_unlock_read(map);
		break;
	case MEM_KERNELDUMP:
		marg = (const struct mem_livedump_arg *)data;
		error = livedump_start(marg->fd, marg->flags, marg->compression);
		break;
#if __has_feature(capabilities)
#ifdef COMPAT_FREEBSD64
	case MEM_READ_CHERI_CAP64:
		cap_arg64 = (const struct mem_cheri_cap_arg64 *)data;
		cap_arg_thunk.vaddr = cap_arg64->vaddr;
		cap_arg_thunk.buf = __USER_CAP(cap_arg64->buf, cap_arg64->len);
		cap_arg_thunk.len = cap_arg64->len;
		error = mem_read_cheri_caps(dev, &cap_arg_thunk);
		break;
#endif
	case MEM_READ_CHERI_CAP:
		cap_arg = (const struct mem_cheri_cap_arg *)data;
		error = mem_read_cheri_caps(dev, cap_arg);
		break;
#endif
	default:
		error = memioctl_md(dev, cmd, data, flags, td);
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
mem_modevent(module_t mod __unused, int type, void *data __unused)
{
	switch(type) {
	case MOD_LOAD:
		if (bootverbose)
			printf("mem: <memory>\n");
		mem_range_init();
		memdev = make_dev(&mem_cdevsw, CDEV_MINOR_MEM,
			UID_ROOT, GID_KMEM, 0640, "mem");
		kmemdev = make_dev(&mem_cdevsw, CDEV_MINOR_KMEM,
			UID_ROOT, GID_KMEM, 0640, "kmem");
		break;

	case MOD_UNLOAD:
		mem_range_destroy();
		destroy_dev(memdev);
		destroy_dev(kmemdev);
		break;

	case MOD_SHUTDOWN:
		break;

	default:
		return(EOPNOTSUPP);
	}

	return (0);
}

DEV_MODULE(mem, mem_modevent, NULL);
MODULE_VERSION(mem, 1);
