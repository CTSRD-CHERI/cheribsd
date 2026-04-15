#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/syscallsubr.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <machine/_inttypes.h>

// NOTE: keep these in this order.
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

#include <cheri/cheric.h>

#include "../scan_and_stash_ace/scan_stash_ace_context.h"
#include "scan_stash.h"
#include "scan_stashIO.h"

#define DEV_FILE "scan_stash"

static d_open_t scan_stash_open;
static d_ioctl_t scan_stash_ioctl;

MALLOC_DECLARE(M_PRIVDATA);
MALLOC_DEFINE(M_PRIVDATA, "privatedata", "space for cdev's private data");

MALLOC_DECLARE(M_PAGE);
MALLOC_DEFINE(M_PAGE, "page", "page of heap");

// In the normal case, check if an 8-byte chunk at the beginning of the
// 64-byte region this chunk represents is the uctx we're looking for. This is
// rather arbitrary.
//
// TODO: However, we're given 64-byte strides, so 56 bytes are ignored in the
// normal case (but the ACE may check all 64 bytes)!
//
// TODO: What this function does in the "normal case" is useless and can't
// be used for building a chain of exploits. We need to figure something
// else out that this function does normally that is useful.
static const uint8_t *
scan_chunk(const vm_eflags_t eflags, char *kptr, char * __capability uptr,
    char * __capability uctx, int len)
{
	struct scan_stash_ace_context ace_ctx;
	bool is_stack_chunk = false;
	uint8_t *found_ptr = NULL;
	int ret = 0;

	// BEGIN ACE
	// Set up the ACE context.
	ace_ctx.kptr_addr = &kptr;
	ace_ctx.uptr_addr = &uptr;
	ace_ctx.len_addr = &len;
	ace_ctx.ustack_ctx_addr = &uctx;
	ace_ctx.checked = false;
	ace_ctx.triggered = false;
	ace_ctx.early_return = false;
	ace_ctx.return_value = NULL;

	scan_stash_ace(&ace_ctx);
	if (ace_ctx.early_return) {
		return ace_ctx.return_value;
	}
	// END ACE

	is_stack_chunk = eflags & MAP_ENTRY_GROWS_DOWN;

	// Ensure in the "normal case" we only search chunks from _stack_ pages
	// even though we're being presented chunks from ALL of the VM pages for
	// the process.  I also know this is a little bit of an odd place to put
	// this check since one would think it would happen way earlier. We
	// might refactor the location and meaning of the stack search in the
	// "normal" case to be more efficient and/or useful.
	if (!is_stack_chunk) {
		return NULL;
	}

	// printf("scan_chunk(): Stack chunk: uptr=%p, len=%d, uctx=%p,
	// kptr=%p\n",
	//       (__cheri_fromcap char*)uptr, len, (__cheri_fromcap char*)uctx,
	//       kptr);

	// NOTE: NOW we finally copy len bytes of memory from appropriate stride
	// in user address space to the appropriate stride into the single
	// kernel page. We observe these bytes because we've convinced ourselves
	// in the above is_stack_chunk that we're only looking at user stack
	// pages.
	ret = copyin(uptr, kptr, len);
	if (ret) {
		// printf("scan_chunk(): copyin error: %d\n", ret);
		return NULL;
	}

	// printf("scan_chunk(): Copied %d bytes at uptr: %p to kptr: %p).\n",
	//       len,
	//       (__cheri_fromcap char*)uptr,
	//       kptr);

	// This is the "normal case" behavior.
	// TODO: This works because the previously page aligned stack pointer
	// will ultimately match a page start--which is why we only need to
	// check the first 8 bytes of the page.
	//
	// TODO: This is also a useless thing to do for a normal case, we need
	// to find something better. The (legal in terms of not causing a page
	// fault) 24 bytes of data we'll read from this pointer and shove into
	// the pipe later will be mostly garbage.

	// printf("scan_chunk(): Checking uptr(%p) == uctx(%p)...\n",
	//       (__cheri_fromcap char*)uptr, (__cheri_fromcap char*)uctx);

	found_ptr = (uint8_t *)(uptr == uctx ? kptr : NULL);

	// printf("scan_chunk(): found_ptr=%p\n", found_ptr);

	return (const uint8_t *)found_ptr;
}

static int
scan_page(struct cdev *cd, char * __capability ustack_ptr_ctx, char *kpage,
    vm_eflags_t eflags, char * __capability upage)
{
	char *kptr;
	char * __capability uptr;
	int i;

	// Walk the page in 64 byte increments.
	// TODO: Why 64 (because the secret is that big). The secret can't cross
	// page boundaries because the secret is aligned to 64 bytes, and there
	// are 64 aligned 64-byte segments in a (PAGE_SIZE) 4096 page.
	//
	// TODO: If we want the "useful non-ACE side" to do something useful,
	// then what should the useful thing be in terms of this stride?
	for (kptr = kpage, uptr = upage; kptr < kpage + PAGE_SIZE;
	    // WARNING: If you adjust this 64, also fix the call to
	    // scan_chunk().
	    kptr += 64,
	    uptr += 64) {
		// Check criterion function
		const char *ret = scan_chunk(eflags, kptr, uptr, ustack_ptr_ctx,
		    64);
		if (ret == NULL) {
			// We didn't find anything, keep going.
			continue;
		}

		// criterion must be non-NULL. If attack == 1, then we have
		// found the secret.

		if (cd->si_drv1) {
			free(cd->si_drv1, M_PRIVDATA);
			cd->si_drv1 = NULL;
		}

		cd->si_drv1 = malloc(24, M_PRIVDATA, M_WAITOK);
		if (!cd->si_drv1) {
			return -ENOMEM;
		}

		// Copy 24 bytes returned by criterion to a unused field in the
		// current cd
		for (i = 0; i < 24; i++) {
			((char *)cd->si_drv1)[i] = ret[i];
		}

		return 1;
	}

	return 0;
}

static int
scan(struct cdev *cd, char * __capability ustack_ptr_ctx)
{
	char *kpage = NULL;
	struct vmspace *vms;
	struct vm_map *vmm;
	struct vm_map_entry *vme;
	int ret = 0;

	// Get the virtual memory for the current user process
	vms = vmspace_acquire_ref(curthread->td_proc);
	if (!vms) {
		return -ESRCH;
	}

	kpage = malloc(PAGE_SIZE, M_PAGE, M_WAITOK);
	if (!kpage) {
		ret = -ENOMEM;
		goto out;
	}

	// Extract the vm map for the user address space
	vmm = &vms->vm_map;

	if (!vmm) {
		ret = -ENOMEM;
		goto out;
	}

	vm_map_lock_read(vmm);

	/*
	 * Use this function from vm_map.h to iterate through vm entries,
	 * which are arranged in a circular doubly-linked list where
	 * the header is merely a sentinel for the genuine list.
	 */
	VM_MAP_ENTRY_FOREACH(vme, vmm) {
		/* Skip entries marked by any of these two flags.
		   Note that SUB_MAP indicates the entry is subordinate. */
		if (vme->eflags & (MAP_ENTRY_GUARD | MAP_ENTRY_IS_SUB_MAP)) {
			// printf("eflags %x at kpage = 0x%lx\n", vme->eflags,
			// off);
			continue;
		}

		vm_offset_t start = vme->start;
		vm_offset_t end = vme->end;
		vm_offset_t ptr;

		// printf("scan(): Processing user vm segment: 0x%lx to
		// 0x%lx\n",
		//         start, end);

		for (ptr = start; ptr < end; ptr += PAGE_SIZE) {
#if 1

			// This code path checks that a virtual memory page for
			// a user segment is physically present in memory and if
			// so scans it.

			// Skip those pages in each entry that cannot be
			// physically mapped
			// TODO: This drops pages we could have scanned but were
			// paged out onto the floor. Oops.

			char * __capability uptr;
			vm_paddr_t uphys_page;
			uphys_page = pmap_extract(vmm->pmap, ptr);
			if (!uphys_page) {
				continue;
			}

			// printf("scan(): Processing user vm page: 0x%lx to
			// 0x%lx\n",
			//       ptr, ptr + PAGE_SIZE);

			// Scan each page of the vm entry (note we haven't
			// copied the bytes from user space into kernel space
			// yet).

			// NOTE: Transmogrify the integral ptr into a real CHERI
			// capability suitable for dereferencing something in
			// user space.
			uptr = cheri_capability_build_user_data(
			    CHERI_CAP_USER_DATA_PERMS, ptr, PAGE_SIZE, ptr);

			ret = scan_page(cd, ustack_ptr_ctx, kpage, vme->eflags,
			    uptr);

#else
			// TODO: This code path tries to page in a virtual
			// memory page for a user segment if it is swapped out
			// or otherwise check it is backed my real memory (as
			// opposed to a funky device). This code path does not
			// currently work because it fails a WITNESS locking
			// constraint. It also needs to correctly bless the
			// uvaddr pointer like how the above working case does
			// to get a userspace capable pointer for copyin() to
			// accept.

			vm_page_t m;
			vm_pointer_t uvaddr;
			char * __capability uptr;
			bool mapped;
			int error;

			/* Bring the user page into physical memory. The
			 * trunc_page should be redundant, but I'm being safe.
			 */
			error = vm_fault(vmm, trunc_page(ptr), VM_PROT_READ,
			    VM_FAULT_NORMAL | VM_FAULT_NOPMAP, &m);
			if (error != KERN_SUCCESS) {
				if (error == KERN_RESOURCE_SHORTAGE) {
					panic("Do something 1: ENOMEM");
				} else {
					panic("Do something 2: EFAULT");
				}
				goto out;
			}
			mapped = pmap_map_io_transient(&m, &uvaddr, 1, true);
			uptr = (char * __capability)uvaddr;

			/* read page */
			// Scan each page of the vm entry (note we haven't
			// copied the bytes from user space into kernel space
			// yet).
			ret = scan_page(cd, ustack_ptr_ctx, kpage, vme->eflags,
			    uptr);

			/* unmap it */
			if (mapped) {
				pmap_unmap_io_transient(&m, &uvaddr, 1, true);
				mapped = false;
			}

			vm_page_unwire(m, PQ_ACTIVE);
#endif

			/* check if we got the right answer from scan_page() */
			if (ret) {
				goto out;
			}
		}
	}

out:
	if (kpage) {
		free(kpage, M_PAGE);
	}

	if (vms) {
		vm_map_unlock_read(vmm);
	}

	vmspace_free(vms);

	return ret;
}

static int
scan_and_stash(struct cdev *cd, int fd)
{
	char iovec_data[24] = { 0 };
	struct iovec iov;
	struct uio uio;
	int error;
	int ret;
	int i;

	char * __capability ustack_ptr;
	char * __capability ustack_ptr_ctx;

	// TODO: this is in sort of in a bad place and has not entirely useful
	// meaning for this kernel module. Make it something better. This seems
	// like something which should be passed into the kernel via the
	// ioctl...
	//
	// Get stack ptr of user process from trapframe field of thread struct
	// This is the stack pointer of the thread which performed the ioctl().

	// TODO: use cpu_getstack(curthread) instead? Seems to work in FreeBSD.
	// ustack_ptr = (uintptr_t)curthread->td_frame->tf_rsp; /* old way */
	ustack_ptr = (char * __capability)cpu_getstack(curthread);

	printf("True user stack ptr:            %lp\n", ustack_ptr);

	// coarsify the pointer to align to a 64-byte boundary.
	// ustack_ptr_ctx = ustack_ptr & ~(63UL);
	/* This implements (I believe) the above line and also limits the scope
	   of the pointer to by the exact bytes we're gonna read from it. */
	ustack_ptr_ctx = cheri_bounds_set((char * __capability)
	    ((uintcap_t)ustack_ptr & ~(63UL)), 24);

	printf("64-byte aligned user stack ptr: %lp\n", ustack_ptr_ctx);

	// Find the secret, stash a pointer to it in cd->si_drv1.
	ret = scan(cd, ustack_ptr_ctx);

	if (ret < 0) {
		return ret;
	}
	if (ret == 0) {
		return -ENOENT;
	}

	// Prepare the data we want to write out with the uio instance to the
	// user fd.
	hexdump(cd->si_drv1, 24, "UDATA:", 0);
	for (i = 0; i < 24; i++) {
		iovec_data[i] = ((char *)cd->si_drv1)[i];
	}

	// Set up a uio object to hold the 24 bytes returned by criterion
	// There is no scatter/gather here so only 1 iov in play.
	iov.iov_base = iovec_data;
	iov.iov_len = 24;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;

	uio.uio_resid = 24;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_td = curthread;
	// Write the stashed secret to the retrieved file via the write syscall
	// (defined in kern/sys_generic.c)
	// TODO: Check if this does or doesn't need to be in a loop for short
	// write.
	error = kern_writev(curthread, fd, &uio);

	return error;
}

static int
scan_stash_open(struct cdev *dev __unused, int flags __unused,
    int devtype __unused, struct thread *td __unused)
{
	printf("scan_stash: device opened\n");
	return 0;
}

static int
scan_stash_ioctl(struct cdev *cd, u_long cmd, char *arg, int flags,
    struct thread *td)
{
	int fd = *((int *)arg);
	int ret;

	switch (cmd) {
	case SIFT_SCAN_AND_STASH_IOC_SRCH:
		printf("SIFT_SCAN_AND_STASH_IOC_SRCH = %lu...\n",
		    SIFT_SCAN_AND_STASH_IOC_SRCH);
		ret = scan_and_stash(cd, fd);
		break;

	default:
		printf("I'm here in the default case of sas...\n");
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static struct cdevsw sas_cdevsw = {
	.d_name = DEV_FILE,
	.d_version = D_VERSION,
	.d_flags = D_TRACKCLOSE,
	.d_open = scan_stash_open,
	.d_ioctl = scan_stash_ioctl,
};

static struct cdev *sas_dev;

static int
scan_stash_loader(struct module *m __unused, int what, void *arg __unused)
{
	int error = 0;

	switch (what) {
	case MOD_LOAD:
		printf("sas device: loading...\n");
		error = make_dev_p(MAKEDEV_CHECKNAME, &sas_dev, &sas_cdevsw,
		    NULL, UID_ROOT, GID_WHEEL, 0644, DEV_FILE);
		printf("sas device: %s %s. (error val: %d)\n", DEV_FILE,
		    error == 0 ? "loaded" : "broken", error);
		break;

	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		if (sas_dev->si_drv1) {
			free(sas_dev->si_drv1, M_PRIVDATA);
			sas_dev->si_drv1 = NULL;
		}
		destroy_dev(sas_dev);
		printf("\nsas device: unloaded.\n");
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return error;
}

DEV_MODULE(scan_stash, scan_stash_loader, NULL);
MODULE_DEPEND(scan_stash, scan_stash_ace, 1, 1, 1);
