/*-
 * Copyright (c) 2025 John Baldwin <john@araratriver.co>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <cheri/cheric.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>

static d_open_t ace2_open;
static d_read_t ace2_data_rdwr;
static d_read_t ace2_capability_rdwr;

static struct cdevsw ace2_data_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "ace2_data",
	.d_open = ace2_open,
	.d_read = ace2_data_rdwr,
	.d_write = ace2_data_rdwr
};

static struct cdevsw ace2_capability_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "ace2_capability",
	.d_open = ace2_open,
	.d_read = ace2_capability_rdwr,
	.d_write = ace2_capability_rdwr
};

static int
ace2_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	int error = 0;

	/* Require same permissions as /dev/kmem. */
	if (oflags & FREAD)
		error = priv_check(td, PRIV_KMEM_READ);
	if (oflags & FWRITE) {
		if (error == 0)
			error = priv_check(td, PRIV_KMEM_WRITE);
		if (error == 0)
			error = securelevel_gt(td->td_ucred, 0);
	}

	return (error);
	
}

static int
validate_kva_range(vm_offset_t va, size_t len, vm_prot_t prot)
{
	vm_offset_t page_off;

	if (va + len < va)
		return (EINVAL);

	page_off = va % PAGE_SIZE;
	va = trunc_page(va);
	len += page_off;

	if (VIRT_IN_DMAP(va)) {
		if (!VIRT_IN_DMAP(va + len - 1))
			return (EFAULT);
	} else {
		if (!kernacc((void *)(uintptr_t)va, len, prot))
			return (EFAULT);
	}

	return (0);
}
	
static int
ace2_data_rdwr(struct cdev *dev, struct uio *uio, int ioflag)
{
	void *kva;
	int error;
	bool read = uio->uio_rw == UIO_READ;
	size_t len = uio->uio_resid;

	error = validate_kva_range(uio->uio_offset, len, read ? VM_PROT_READ :
	    VM_PROT_WRITE);
	if (error != 0)
		return (error);

	/*
	 * XXX: This is racey if KVA mappings change while blocked in
	 * uiomove.  For the purposes of this module, that is fine.
	 *
	 * NB: kernel_root_cap is part of the TCB and any sensible
	 * c18n policy would normally forbid direct access to it in
	 * other compartments.  The bounds on `kva` are also best-effort
	 * and may end up overly-broad.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	kva = cheri_setaddress(kernel_root_cap, uio->uio_offset);
	kva = cheri_setbounds(kva, len);
#else
	kva = (void *)(uintptr_t)uio->uio_offset;
#endif
	error = uiomove(kva, uio->uio_resid, uio);
	if (error != 0) {
		printf("%s EFAULT %zu bytes at %p\n", read ? "ACE2_READ_DATA" :
		    "ACE2_WRITE_DATA", len, kva);
	} else {
		printf("%s %zu bytes at %p\n", read ? "ACE2_READ_DATA" :
		    "ACE2_WRITE_DATA", len, kva);
	}
	return (error);
}

static int
ace2_capability_rdwr(struct cdev *dev, struct uio *uio, int ioflag)
{
	uintptr_t *kva;
	int error;
	bool read = uio->uio_rw == UIO_READ;
	size_t len = uio->uio_resid;
	size_t nptrs;

	if (len % sizeof(ptraddr_t) != 0 ||
	    !is_aligned(uio->uio_offset, sizeof(void *)))
		return (EINVAL);

	nptrs = len / sizeof(ptraddr_t);
	len = nptrs * sizeof(void *);
	error = validate_kva_range(uio->uio_offset, len, read ? VM_PROT_READ :
	    VM_PROT_WRITE);
	if (error != 0)
		return (error);

	/* Comments in ace2_data_rdwr apply here as well. */
#ifdef __CHERI_PURE_CAPABILITY__
	kva = cheri_setaddress(kernel_root_cap, uio->uio_offset);
	kva = cheri_setbounds(kva, len);
	for (size_t i = 0; i < nptrs; i++) {
		ptraddr_t addr;

		if (read)
			addr = cheri_getaddress(kva[i]);
		
		error = uiomove(&addr, sizeof(addr), uio);
		if (error != 0)
			break;

		if (!read)
			kva[i] = cheri_setaddress(kva[i], addr);
	}
#else
	kva = (void *)(uintptr_t)uio->uio_offset;
	error = uiomove(kva, uio->uio_resid, uio);
#endif
	if (error != 0) {
		printf("%s EFAULT %zu pointers at %p\n",
		    read ? "ACE2_READ_CAPABILITY" : "ACE2_WRITE_CAPABILITY",
		    nptrs, kva);
	} else {
		printf("%s %zu pointers at %p\n",
		    read ? "ACE2_READ_CAPABILITY" : "ACE2_WRITE_CAPABILITY",
		    nptrs, kva);
	}
	return (error);
}

static int
ace2_modevent(module_t mod, int type, void *data)
{
	static struct cdev *ace2_data;
	static struct cdev *ace2_capability;

	switch (type) {
	case MOD_LOAD:
		ace2_data = make_dev(&ace2_data_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0600, "ace2-ace-data");
		ace2_capability = make_dev(&ace2_capability_cdevsw, 0,
		    UID_ROOT, GID_WHEEL, 0600, "ace2-ace-capability");
		return (0);
	case MOD_UNLOAD:
		destroy_dev(ace2_data);
		destroy_dev(ace2_capability);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

DEV_MODULE(ace2, ace2_modevent, NULL);
