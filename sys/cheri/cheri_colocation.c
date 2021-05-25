/*-
 * Copyright (c) 2018 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/unistd.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_map.h>

#ifdef DDB
#include <ddb/ddb.h>
#include <sys/kdb.h>
#endif

extern void * __capability	userspace_cap;

/*
 * Capability used to seal capability pairs returned by cosetup(2).
 */
void * __capability	switcher_sealcap = (void * __capability)-1;

/*
 * Capability used to seal capabilities returned by coregister(2)/colookup(2).
 */
void * __capability	switcher_sealcap2 = (void * __capability)-1;

struct sx		switcher_lock;

#define	SWITCHER_LOCK()		sx_xlock(&switcher_lock)
#define	SWITCHER_UNLOCK()	sx_xunlock(&switcher_lock)

static int colocation_debug;
SYSCTL_INT(_debug, OID_AUTO, colocation_debug, CTLFLAG_RWTUN,
    &colocation_debug, 0, "Enable process colocation debugging");
static int counregister_on_exit = 1;
SYSCTL_INT(_debug, OID_AUTO, counregister_on_exit, CTLFLAG_RWTUN,
    &counregister_on_exit, 0, "Remove dead conames on thread exit");

#ifdef DDB
static int kdb_on_switcher_trap;
SYSCTL_INT(_debug, OID_AUTO, kdb_on_switcher_trap, CTLFLAG_RWTUN,
    &kdb_on_switcher_trap, 0, "Enter ddb(4) on switcher traps");
static int kdb_on_unborrow;
SYSCTL_INT(_debug, OID_AUTO, kdb_on_unborrow, CTLFLAG_RWTUN,
    &kdb_on_unborrow, 0, "Enter ddb(4) on thread unborrow");
#endif

#define	COLOCATION_DEBUG(X, ...)					\
	do {								\
		if (colocation_debug > 0)				\
			printf("%s: " X "\n", __func__, ## __VA_ARGS__);\
	} while (0)

static void
colocation_startup(void)
{

	sx_init(&switcher_lock, "switchersx");
}
SYSINIT(colocation_startup, SI_SUB_CPU, SI_ORDER_FIRST, colocation_startup,
    NULL);

void
colocation_cleanup(struct thread *td)
{
	td->td_md.md_scb = 0;
}

static void
colocation_copyin_scb_atcap(const void * __capability cap,
    struct switchercb *scbp)
{
	int error;

	KASSERT(cap != NULL, ("%s: NULL addr", __func__));

	error = copyincap(cap, &(*scbp), sizeof(*scbp));
	KASSERT(error == 0, ("%s: copyincap from %#lp failed with error %d\n",
	    __func__, cap, error));
}

static void
colocation_copyin_scb_at(const void *addr, struct switchercb *scbp)
{

	return (colocation_copyin_scb_atcap(
	    ___USER_CFROMPTR(addr, userspace_cap), scbp));
}

void * __capability
colocation_get_codecap(struct thread *td, int what)
{
	void * __capability codecap;

	switch (what) {
	case COSETUP_COCALL:
		/*
		 * XXX: This should should use cheri_capability_build_user_code()
		 *      instead.  It fails to seal, though; I guess there's something
		 *      wrong with perms.
		 */
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cocall_base,
		    td->td_proc->p_sysent->sv_cocall_len, 0);
		break;

	case COSETUP_COACCEPT:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_coaccept_base,
		    td->td_proc->p_sysent->sv_coaccept_len, 0);
		break;

	case COSETUP_COGETPID:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cogetpid_base,
		    td->td_proc->p_sysent->sv_cogetpid_len, 0);
		break;

	case COSETUP_COGETTID:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cogettid_base,
		    td->td_proc->p_sysent->sv_cogettid_len, 0);
		break;

	default:
		return (NULL);
	}

#ifdef CHERI_FLAGS_CAP_MODE
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI))
		codecap = cheri_setflags(codecap, CHERI_FLAGS_CAP_MODE);
#endif
	codecap = cheri_seal(codecap, switcher_sealcap);

	return (codecap);
}

void * __capability
colocation_get_scbcap(struct thread *td)
{
	void * __capability datacap;
	vaddr_t addr;

	addr = td->td_md.md_scb;
	if (addr == 0)
		return (NULL);

	datacap = cheri_capability_build_user_data(CHERI_CAP_USER_DATA_PERMS,
	    addr, PAGE_SIZE, 0);
	datacap = cheri_seal(datacap, switcher_sealcap);

	return (datacap);
}

static bool
colocation_fetch_scb(struct thread *td, struct switchercb *scbp)
{
	vaddr_t addr;

	addr = td->td_md.md_scb;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	colocation_copyin_scb_at((const void *)addr, scbp);

	return (true);
}

static void
colocation_copyout_scb_atcap(void * __capability cap, const struct switchercb *scbp)
{
	int error;

	KASSERT(cap != NULL, ("%s: NULL addr", __func__));

	error = copyoutcap(scbp, cap, sizeof(*scbp));
	KASSERT(error == 0, ("%s: copyoutcap to %#lp failed with error %d",
	    __func__, cap, error));
}

static void
colocation_copyout_scb_at(void *addr, const struct switchercb *scbp)
{

	return (colocation_copyout_scb_atcap(
	    ___USER_CFROMPTR(addr, userspace_cap), scbp));
}

static void
colocation_copyout_scb(struct thread *td, struct switchercb *scbp)
{

	colocation_copyout_scb_at((void *)td->td_md.md_scb, scbp);
}

static bool
colocation_fetch_caller_scb(struct thread *td, struct switchercb *scbp)
{
	vaddr_t addr;

	addr = td->td_md.md_scb;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	colocation_copyin_scb_at((void *)addr, scbp);

	if (cheri_gettag(scbp->scb_caller_scb) == 0 ||
	    cheri_getlen(scbp->scb_caller_scb) == 0) {
		/*
		 * Not in cocall.
		 */
		return (false);
	}

	colocation_copyin_scb_atcap(scbp->scb_caller_scb, scbp);

	return (true);
}

static bool
colocation_fetch_callee_scb(struct thread *td, struct switchercb *scbp)
{
	vaddr_t addr;

	addr = td->td_md.md_scb;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	colocation_copyin_scb_at((const void *)addr, scbp);

	if (cheri_gettag(scbp->scb_callee_scb) == 0 ||
	    cheri_getlen(scbp->scb_callee_scb) == 0) {
		/*
		 * Not in cocall.
		 */
		return (false);
	}

	colocation_copyin_scb_atcap(scbp->scb_callee_scb, scbp);

	return (true);
}

static void
wakeupcap(const void * __capability target, const char *who)
{
	const void *chan;

	chan = (__cheri_fromcap const void *)target;
	COLOCATION_DEBUG("waking up %s scb %p", who, chan);
	wakeup(chan);
}

/*
 * This function is intended to wake up threads waiting
 * on this thread's SCB.
 */
static void
wakeupself(void)
{
	const void *chan;

	chan = (const void *)curthread->td_md.md_scb;

	COLOCATION_DEBUG("waking up scb %p", chan);
	wakeup(chan);
}

void
colocation_get_peer(struct thread *td, struct thread **peertdp)
{
	struct switchercb scb;
	bool have_scb;

	have_scb = colocation_fetch_scb(td, &scb);
	if (!have_scb) {
		*peertdp = NULL;
		return;
	}

	*peertdp = scb.scb_borrower_td;
}

void
colocation_thread_exit(struct thread *td)
{
	struct vmspace *vmspace;
	struct coname *con, *con_temp;
	struct mdthread *md;
	struct switchercb scb;
	bool have_scb;

	have_scb = colocation_fetch_scb(td, &scb);
	if (!have_scb)
		return;

	if (counregister_on_exit) {
		vmspace = td->td_proc->p_vmspace;

		vm_map_lock(&vmspace->vm_map);

		LIST_FOREACH_SAFE(con, &vmspace->vm_conames, c_next, con_temp) {
			if (cheri_getaddress(con->c_value) == td->td_md.md_scb) {
				LIST_REMOVE(con, c_next);
				free(con, M_TEMP);
			}
		}

		vm_map_unlock(&vmspace->vm_map);
	}

	md = &td->td_md;

	/*
	 * Wake up any thread waiting on cocall_slow(2).
	 */
	wakeupself();

	COLOCATION_DEBUG("terminating thread %p, scb %p",
	    td, (void *)td->td_md.md_scb);

	/*
	 * Set scb_caller_scb to a special "null" capability, so that cocall(2)
	 * can see the callee thread is dead.
	 */
	scb.scb_caller_scb = cheri_capability_build_user_data(0, 0, 0, EPIPE);
	scb.scb_td = NULL;
	scb.scb_borrower_td = NULL;

	colocation_copyout_scb(td, &scb);
	td->td_md.md_scb = 0;
}

/*
 * Assign our trapframe (userspace context) to the thread waiting
 * in copark(2) and wake it up; it'll return to userspace with ERESTART
 * and then bounce back.
 *
 * Called from trap().
 */
void
colocation_unborrow(struct thread *td)
{
	struct switchercb scb;
	struct thread *peertd;
	struct trapframe *trapframe, peertrapframe;
#ifdef __mips__
	trapf_pc_t peertpc;
#endif
	bool have_scb;

	have_scb = colocation_fetch_scb(td, &scb);
	if (!have_scb)
		return;

	trapframe = td->td_frame;
	peertd = scb.scb_borrower_td;
	if (peertd == NULL) {
		/*
		 * Nothing borrowed yet.
		 */
		return;
	}

	KASSERT(td == scb.scb_td,
	    ("%s: td %p != scb_td %p\n", __func__, td, scb.scb_td));
	KASSERT(peertd != td,
	    ("%s: peertd %p == td %p\n", __func__, peertd, td));

#ifdef __mips__
	COLOCATION_DEBUG("replacing current td %p, pid %d (%s), switchercb %#lx, "
	    "md_tls %p, md_tls_tcb_offset %zd, "
	    "with td %p, pid %d (%s), switchercb %#lx, "
	    "md_tls %p, md_tls_tcb_offset %zd, "
	    "due to syscall %u",
	    td, td->td_proc->p_pid, td->td_proc->p_comm, td->td_md.md_scb,
	    (__cheri_fromcap void *)td->td_md.md_tls, td->td_proc->p_md.md_tls_tcb_offset,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm, peertd->td_md.md_scb,
	    (__cheri_fromcap void *)peertd->td_md.md_tls, peertd->td_proc->p_md.md_tls_tcb_offset,
	    td->td_sa.code);
#else
	COLOCATION_DEBUG("replacing current td %p, pid %d (%s), switchercb %#lx, "
	    "with td %p, pid %d (%s), switchercb %#lx due to syscall %u",
	    td, td->td_proc->p_pid, td->td_proc->p_comm, td->td_md.md_scb,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm, peertd->td_md.md_scb,
	    td->td_sa.code);
#endif

#ifdef DDB
	if (kdb_on_unborrow)
		kdb_enter(KDB_WHY_CHERI, "unborrow");
#endif

#ifdef __mips__
	KASSERT(td->td_frame == &td->td_pcb->pcb_regs,
	    ("%s: td->td_frame %p != &td->td_pcb->pcb_regs %p, td %p",
	    __func__, td->td_frame, &td->td_pcb->pcb_regs, td));

	KASSERT(peertd->td_frame == &peertd->td_pcb->pcb_regs,
	    ("%s: peertd->td_frame %p != &peertd->td_pcb->pcb_regs %p, peertd %p",
	    __func__, peertd->td_frame, &peertd->td_pcb->pcb_regs, peertd));

	/*
	 * Another MIPS-specific field; this one needs to be swapped.
	 */
	peertpc = peertd->td_pcb->pcb_tpc;
	peertd->td_pcb->pcb_tpc = td->td_pcb->pcb_tpc;
	td->td_pcb->pcb_tpc = peertpc;
#endif

	memcpy(&peertrapframe, peertd->td_frame, sizeof(struct trapframe));
	memcpy(peertd->td_frame, td->td_frame, sizeof(struct trapframe));
	memcpy(td->td_frame, &peertrapframe, sizeof(struct trapframe));

	/*
	 * Wake up the other thread, which should return with ERESTART,
	 * refetch its args from the updated trapframe, and then execute
	 * whatever syscall we've just entered.
	 */
	wakeup(&peertd->td_md.md_scb);

	/*
	 * Continue as usual, but calling copark(2) instead of whatever
	 * syscall it was.  The cpu_fetch_syscall_args() will fetch updated
	 * arguments from the stack frame.
	 */
#ifdef __mips__
	KASSERT(td->td_frame->v0 == SYS_copark,
	    ("%s: td_sa.code %ld != SYS_copark %d; peer td_sa.code %ld; td %p, pid %d (%s); peer td %p, peer pid %d (%s)\n",
	    __func__, (long)td->td_frame->v0, SYS_copark, (long)peertd->td_frame->v0,
	    td, td->td_proc->p_pid, td->td_proc->p_comm,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm));
#elif defined(__riscv)
	KASSERT(td->td_frame->tf_t[0] == SYS_copark,
	    ("%s: td_sa.code %ld != SYS_copark %d; peer td_sa.code %ld; td %p, pid %d (%s); peer td %p, peer pid %d (%s)\n",
	    __func__, (long)td->td_frame->tf_t[0], SYS_copark, (long)peertd->td_frame->tf_t[0],
	    td, td->td_proc->p_pid, td->td_proc->p_comm,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm));
#else
#error "what architecture is this?"
#endif

	scb.scb_borrower_td = NULL;
	colocation_copyout_scb(td, &scb);
}

bool
colocation_trap_in_switcher(struct thread *td, struct trapframe *trapframe,
    const char *msg)
{
	const struct sysentvec *sv;
	vm_offset_t addr;

	sv = td->td_proc->p_sysent;
#if defined(__mips__)
	addr = (__cheri_addr vaddr_t)trapframe->pc;
#elif defined(__riscv)
	addr = (__cheri_addr vaddr_t)trapframe->tf_sepc;
#else
#error "what architecture is this?"
#endif

	if (addr >= sv->sv_cocall_base && addr < sv->sv_cocall_base + sv->sv_cocall_len)
		goto trap;
	if (addr >= sv->sv_coaccept_base && addr < sv->sv_coaccept_base + sv->sv_coaccept_len)
		goto trap;
	return (false);
trap:
	COLOCATION_DEBUG("%s in switcher", msg);
#ifdef DDB
	if (kdb_on_switcher_trap)
		kdb_enter(KDB_WHY_CHERI, msg);
#endif
	return (true);
}

#ifdef __mips__
void
colocation_update_tls(struct thread *td)
{
	vaddr_t addr;
	struct switchercb scb;

	addr = td->td_md.md_scb;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return;
	}

	colocation_copyin_scb_at((void *)addr, &scb);
	COLOCATION_DEBUG("changing TLS from %p to %p",
	    (__cheri_fromcap void *)scb.scb_tls,
	    (__cheri_fromcap void *)((char * __capability)td->td_md.md_tls + td->td_proc->p_md.md_tls_tcb_offset));
	scb.scb_tls = (char * __capability)td->td_md.md_tls + td->td_proc->p_md.md_tls_tcb_offset;
	colocation_copyout_scb_at((void *)addr, &scb);
}
#endif

/*
 * Setup the per-thread switcher control block.
 */
static int
setup_scb(struct thread *td)
{
	struct switchercb scb;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_offset_t addr;
	boolean_t found;
	int rv;

	KASSERT(td->td_md.md_scb == 0, ("%s: already initialized\n", __func__));

	map = &td->td_proc->p_vmspace->vm_map;

	vm_map_lock(map);

	addr = vm_map_findspace(map, vm_map_min(map), PAGE_SIZE);
	if (addr + PAGE_SIZE > vm_map_max(map)) {
		COLOCATION_DEBUG("vm_map_findspace() failed");
		vm_map_unlock(map);
		return (ENOMEM);
	}

	rv = vm_map_insert(map, NULL, 0, addr, addr + PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_READ_CAP | VM_PROT_WRITE_CAP,
	    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_READ_CAP | VM_PROT_WRITE_CAP,
	    MAP_DISABLE_COREDUMP, addr);
	if (rv != KERN_SUCCESS) {
		COLOCATION_DEBUG("vm_map_insert() failed with rv %d", rv);
		vm_map_unlock(map);
		return (ENOMEM);
	}

	found = vm_map_lookup_entry(map, addr, &entry);
	KASSERT(found == TRUE,
	    ("%s: vm_map_lookup_entry() returned false\n", __func__));
	entry->owner = 0;

	vm_map_unlock(map);

	td->td_md.md_scb = addr;

	//printf("%s: scb at %p, td %p\n", __func__, (void *)addr, td);
	memset(&scb, 0, sizeof(scb));
	scb.scb_unsealcap = switcher_sealcap2;
	scb.scb_td = td;
	scb.scb_borrower_td = NULL;
	scb.scb_caller_scb = cheri_capability_build_user_data(0, 0, 0, EAGAIN);
#ifdef __mips__
	scb.scb_tls = (char * __capability)td->td_md.md_tls + td->td_proc->p_md.md_tls_tcb_offset;
#elif defined(__riscv)
	scb.scb_pid = td->td_proc->p_pid;
	scb.scb_tid = td->td_tid;
#endif
	colocation_copyout_scb(td, &scb);

	return (0);
}

int
sys__cosetup(struct thread *td, struct _cosetup_args *uap)
{

	return (kern_cosetup(td, uap->what, uap->code, uap->data));
}

int
kern_cosetup(struct thread *td, int what,
    void * __capability * __capability codep,
    void * __capability * __capability datap)
{
	void * __capability codecap;
	void * __capability datacap;
	vaddr_t addr;
	int error;

	KASSERT(switcher_sealcap != (void * __capability)-1,
             ("%s: uninitialized switcher_sealcap", __func__));
	KASSERT(switcher_sealcap2 != (void * __capability)-1,
             ("%s: uninitialized switcher_sealcap2", __func__));
	KASSERT(switcher_sealcap != switcher_sealcap2,
             ("%s: switcher_sealcap == switcher_sealcap2", __func__));

	if (td->td_md.md_scb == 0) {
		error = setup_scb(td);
		if (error != 0)
			return (error);
	}

	addr = td->td_md.md_scb;

	switch (what) {
	case COSETUP_COCALL:
		/*
		 * XXX: This should should use cheri_capability_build_user_code()
		 *      instead.  It fails to seal, though; I guess there's something
		 *      wrong with perms.
		 */
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cocall_base,
		    td->td_proc->p_sysent->sv_cocall_len, 0);
		break;

	case COSETUP_COACCEPT:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_coaccept_base,
		    td->td_proc->p_sysent->sv_coaccept_len, 0);
		break;

	case COSETUP_COGETPID:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cogetpid_base,
		    td->td_proc->p_sysent->sv_cogetpid_len, 0);
		break;

	case COSETUP_COGETTID:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cogettid_base,
		    td->td_proc->p_sysent->sv_cogettid_len, 0);
		break;

	default:
		return (EINVAL);
	}

#ifdef CHERI_FLAGS_CAP_MODE
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI))
		codecap = cheri_setflags(codecap, CHERI_FLAGS_CAP_MODE);
#endif
	codecap = cheri_seal(codecap, switcher_sealcap);
	error = copyoutcap(&codecap, codep, sizeof(codecap));
	if (error != 0)
		return (error);

	datacap = cheri_capability_build_user_data(CHERI_CAP_USER_DATA_PERMS,
	    addr, PAGE_SIZE, 0);
	datacap = cheri_seal(datacap, switcher_sealcap);
	error = copyoutcap(&datacap, datap, sizeof(datacap));
	return (0);
}

int
sys_coregister(struct thread *td, struct coregister_args *uap)
{

	return (kern_coregister(td, uap->name, uap->cap));
}

int
kern_coregister(struct thread *td, const char * __capability namep,
    void * __capability * __capability capp)
{
	struct vmspace *vmspace;
	struct coname *con;
	char name[PATH_MAX];
	void * __capability cap;
	vaddr_t addr;
	int error;

	vmspace = td->td_proc->p_vmspace;

	if (td->td_md.md_scb == 0) {
		error = setup_scb(td);
		if (error != 0)
			return (error);
	}

	if (namep != NULL) {
		error = copyinstr(namep, name, sizeof(name), NULL);
		if (error != 0)
			return (error);

		if (strlen(name) == 0)
			return (EINVAL);

		if (strlen(name) >= PATH_MAX)
			return (ENAMETOOLONG);

		vm_map_lock(&vmspace->vm_map);
		LIST_FOREACH(con, &vmspace->vm_conames, c_next) {
			if (strcmp(name, con->c_name) == 0) {
				vm_map_unlock(&vmspace->vm_map);
				return (EEXIST);
			}
		}
	}

	addr = td->td_md.md_scb;
	cap = cheri_capability_build_user_data(CHERI_CAP_USER_DATA_PERMS,
	    addr, PAGE_SIZE, 0);
	cap = cheri_seal(cap, switcher_sealcap2);

	if (capp != NULL) {
		error = copyoutcap(&cap, capp, sizeof(cap));
		if (error != 0) {
			vm_map_unlock(&vmspace->vm_map);
			return (error);
		}
	}

	if (namep != NULL) {
		con = malloc(sizeof(struct coname), M_TEMP, M_WAITOK);
		con->c_name = strdup(name, M_TEMP);
		con->c_value = cap;
		LIST_INSERT_HEAD(&vmspace->vm_conames, con, c_next);
		vm_map_unlock(&vmspace->vm_map);
	}

	return (0);
}

int
sys_colookup(struct thread *td, struct colookup_args *uap)
{

	return (kern_colookup(td, uap->name, uap->cap));
}

int
kern_colookup(struct thread *td, const char * __capability namep,
    void * __capability * __capability capp)
{
	struct vmspace *vmspace;
	const struct coname *con;
	char name[PATH_MAX];
	int error;

	vmspace = td->td_proc->p_vmspace;

	error = copyinstr(namep, name, sizeof(name), NULL);
	if (error != 0)
		return (error);

	vm_map_lock_read(&vmspace->vm_map);
	LIST_FOREACH(con, &vmspace->vm_conames, c_next) {
		if (strcmp(name, con->c_name) == 0)
			break;
	}

	if (con == NULL) {
		vm_map_unlock_read(&vmspace->vm_map);
		return (ESRCH);
	}

	error = copyoutcap(&con->c_value, capp, sizeof(con->c_value));
	vm_map_unlock_read(&vmspace->vm_map);
	return (error);
}

int
sys_cogetpid(struct thread *td, struct cogetpid_args *uap)
{

	return (kern_cogetpid(td, uap->pidp));
}

int
kern_cogetpid(struct thread *td, pid_t * __capability pidp)
{
	struct switchercb scb;
	bool is_callee;
	pid_t pid;
	int error;

	is_callee = colocation_fetch_caller_scb(td, &scb);
	if (!is_callee)
		return (ESRCH);

	pid = scb.scb_td->td_proc->p_pid;
	error = copyoutcap(&pid, pidp, sizeof(pid));

	return (error);
}

int
sys_copark(struct thread *td, struct copark_args *uap)
{

	return (kern_copark(td));
}

int
kern_copark(struct thread *td)
{
	int error;

	SWITCHER_LOCK();
	error = msleep(&td->td_md.md_scb, &switcher_lock,
	    PPAUSE | PCATCH, "copark", 0);
	SWITCHER_UNLOCK();

	if (error == 0) {
		/*
		 * We got woken up.  This means we got our userspace thread back
		 * (its context is in our trapframe) and we can return with ERESTART,
		 * to "bounce back" and execute the syscall userspace requested.
		 */
		//printf("%s: got switched to, td %p, returning ERESTART\n", __func__, td);
		return (ERESTART);
	} else {
		//printf("%s: error %d, td %p\n", __func__, error, td);
	}

	return (error);
}

int
kern_cocall_slow(void * __capability target,
    const void * __capability outbuf, size_t outlen,
    void * __capability inbuf, size_t inlen)
{
	struct switchercb scb, calleescb;
	struct thread *calleetd;
	int error;
	bool have_scb;

	if (outbuf == NULL) {
		if (outlen != 0) {
			COLOCATION_DEBUG("outbuf == NULL, but outlen != 0, returning EINVAL");
			return (EINVAL);
		}
	} else {
		if (outlen == 0) {
			COLOCATION_DEBUG("outbuf != NULL, but outlen == 0, returning EINVAL");
			return (EINVAL);
		}

		if (outlen > MAXBSIZE) {
			COLOCATION_DEBUG("outlen %zd > %d, returning EMSGSIZE", outlen, MAXBSIZE);
			return (EMSGSIZE);
		}
	}

	if (inbuf == NULL) {
		if (inlen != 0) {
			COLOCATION_DEBUG("inbuf == NULL, but inlen != 0, returning EINVAL");
			return (EINVAL);
		}
	} else {
		if (inlen == 0) {
			COLOCATION_DEBUG("inbuf != NULL, but inlen == 0, returning EINVAL");
			return (EINVAL);
		}

		if (inlen > MAXBSIZE) {
			COLOCATION_DEBUG("inlen %zd > %d, returning EMSGSIZE", inlen, MAXBSIZE);
			return (EMSGSIZE);
		}
	}

	have_scb = colocation_fetch_scb(curthread, &scb);
	if (!have_scb) {
		COLOCATION_DEBUG("no scb, returning EINVAL");
		return (EINVAL);
	}

	/*
	 * Unseal the capability to the callee control block and load it.
	 *
	 * XXX: How to detect unsealing failure?  Would it trap?
	 */
	target = cheri_unseal(target, switcher_sealcap2);

	SWITCHER_LOCK();
again:
	colocation_copyin_scb_atcap(target, &calleescb);

	/*
	 * The protocol here is slightly different from the one used
	 * by the switcher; this is to signal an error when the user
	 * attempts to use kernel {cocall,coaccept}_slow() against
	 * switcher {cocall,coaccept}().  Instead of signalling the
	 * "available" status with NULL capability, instead we encode
	 * it as zero-length capability, with offset set to EPROTOTYPE.
	 */

	if (cheri_gettag(calleescb.scb_caller_scb) == 0) {
		COLOCATION_DEBUG("callee scb %#lp is waiting on switcher cocall", target);
		SWITCHER_UNLOCK();
		return (EPROTOTYPE);
	}

	if (cheri_getlen(calleescb.scb_caller_scb) != 0) {
		/*
		 * Non-zero length means there's already a cocall in progress.
		 */
		COLOCATION_DEBUG("callee is busy, waiting on %#lp", target);
		error = msleep((__cheri_fromcap const void *)target,
		    &switcher_lock, PCATCH, "cobusy", 0);
		if (error != 0) {
			COLOCATION_DEBUG("cobusy msleep failed with error %d",
			    error);
			SWITCHER_UNLOCK();
			return (error);
		}
		goto again;
	}

	error = cheri_getoffset(calleescb.scb_caller_scb);
	/*
	 * EPROTOTYPE means we can proceed with cocall.
	 */
	if (error != EPROTOTYPE) {
		COLOCATION_DEBUG("returning errno %d", error);
		SWITCHER_UNLOCK();
		return (error);
	}

	calleescb.scb_caller_scb =
	    cheri_capability_build_user_data(CHERI_CAP_USER_DATA_PERMS,
	    curthread->td_md.md_scb, PAGE_SIZE, 0);

	/*
	 * XXX: We should be using a capability-sized atomic store
	 *      for scb_caller_scb.
	 */
	colocation_copyout_scb_atcap(target, &calleescb);

	scb.scb_callee_scb = target;
	scb.scb_outbuf = outbuf;
	scb.scb_outlen = outlen;
	scb.scb_inbuf = inbuf;
	scb.scb_inlen = inlen;
	/*
	 * We don't need atomics here; nobody else could have modified
	 * our (caller's) SCB.
	 */
	colocation_copyout_scb(curthread, &scb);

	calleetd = calleescb.scb_td;
	KASSERT(calleetd != NULL, ("%s: NULL calleetd?\n", __func__));

	// XXX: What happens when the callee thread dies while we are here?
	//      We need to hold it somehow.

	/*
	 * Wake up the callee and wait for them to copy the buffer,
	 * return from cocall_slow(2), call cocall_slow(2) again,
	 * and copy the buffer back.
	 */
	wakeupcap(target, "callee");
	COLOCATION_DEBUG("waiting on scb %#lp", target);
	error = msleep((__cheri_fromcap const void *)target,
	    &switcher_lock, PCATCH, "cocall", 0);
	// XXX: Are we sure we are done once we wake up?
	if (error != 0 && error != ERESTART) {
		COLOCATION_DEBUG("msleep failed with error %d", error);
		goto out;
	}

out:
	colocation_copyin_scb_atcap(target, &calleescb);
	calleescb.scb_caller_scb = cheri_capability_build_user_data(0, 0, 0, EPROTOTYPE);
	/*
	 * Here we don't need atomics either; nobody else could have modified
	 * callee's SCB.
	 */
	colocation_copyout_scb_atcap(target, &calleescb);

	/*
	 * Wake up other callers that might be waiting in kern_cocall_slow().
	 */
	wakeupcap(target, "callers sleeping on callee scb");
	SWITCHER_UNLOCK();

	/*
	 * XXX: There is currently no way to return an error to the caller,
	 *      should the copyinout() fail.
	 */

	return (error);
}

int
sys_cocall_slow(struct thread *td, struct cocall_slow_args *uap)
{

	return (kern_cocall_slow(uap->target,
	    uap->outbuf, uap->outlen, uap->inbuf, uap->inlen));
}

static int
copyinout(const void * __capability src, void * __capability dst,
    size_t len, bool from_caller)
{
	void *tmpbuf;
	int error;

	if (len == 0)
		return (0);

	KASSERT(src != NULL, ("%s: NULL src", __func__));
	KASSERT(dst != NULL, ("%s: NULL dst", __func__));

	tmpbuf = malloc(len, M_TEMP, M_WAITOK);
	error = copyincap(src, tmpbuf, len);
	if (error != 0) {
		COLOCATION_DEBUG("copyin from %s failed with error %d",
		    from_caller ? "caller" : "callee", error);
		goto out;
	}
	error = copyoutcap(tmpbuf, dst, len);
	if (error != 0) {
		COLOCATION_DEBUG("copyout to %s failed with error %d",
		    from_caller ? "callee" : "caller", error);
		goto out;
	}
out:
	free(tmpbuf, M_TEMP);
	return (error);
}

int
kern_coaccept_slow(void * __capability * __capability cookiep,
    const void * __capability outbuf, size_t outlen,
    void * __capability inbuf, size_t inlen)
{
	struct switchercb scb, callerscb;
	void * __capability cookie;
	struct mdthread *md, *callermd;
	int error;
	bool have_scb, is_callee;

	md = &curthread->td_md;

	if (outbuf == NULL) {
		if (outlen != 0) {
			COLOCATION_DEBUG("outbuf != NULL, but outlen != 0, returning EINVAL");
			return (EINVAL);
		}
	} else {
		if (outlen == 0) {
			COLOCATION_DEBUG("outbuf != NULL, but outlen == 0, returning EINVAL");
			return (EINVAL);
		}

		if (outlen > MAXBSIZE) {
			COLOCATION_DEBUG("outlen %zd > %d, returning EMSGSIZE", outlen, MAXBSIZE);
			return (EMSGSIZE);
		}
	}

	if (inbuf == NULL) {
		if (inlen != 0) {
			COLOCATION_DEBUG("inbuf != NULL, but inlen != 0, returning EINVAL");
			return (EINVAL);
		}
	} else {
		if (inlen == 0) {
			COLOCATION_DEBUG("inbuf != NULL, but inlen == 0, returning EINVAL");
			return (EINVAL);
		}

		if (inlen > MAXBSIZE) {
			COLOCATION_DEBUG("inlen %zd > %d, returning EMSGSIZE", inlen, MAXBSIZE);
			return (EMSGSIZE);
		}
	}

	have_scb = colocation_fetch_scb(curthread, &scb);
	if (!have_scb) {
		COLOCATION_DEBUG("no scb, returning EINVAL");
		return (EINVAL);
	}

	if (cheri_getlen(scb.scb_caller_scb) == 0) {
		/*
		 * Offset-encoded EPROTOTYPE means there's a cocall_slow(2)
		 * waiting.
		 */
		 scb.scb_caller_scb = cheri_capability_build_user_data(0, 0, 0, EPROTOTYPE);

		/*
		 * No atomics needed here; couldn't have raced with cocall(2),
		 * as it would bounce due to scb_caller_scb not being NULL;
		 * couldn't have raced with coaccept(2), because a thread cannot
		 * call coaccept_slow(2) and coaccept(2) at the same time.
		 */
		colocation_copyout_scb(curthread, &scb);
	} else {
		/*
		 * There's a caller waiting for us, get them their data
		 * and wake them up.
		 */
		is_callee = colocation_fetch_caller_scb(curthread, &callerscb);
		KASSERT(is_callee, ("%s: no caller?", __func__));

		/*
		 * Move data from callee to caller.
		 */
		error = copyinout(outbuf, callerscb.scb_inbuf,
		    MIN(outlen, callerscb.scb_inlen), false);
		callermd = &callerscb.scb_td->td_md;
		if (error != 0) {
			COLOCATION_DEBUG("copyinout error %d, waking up %p",
			    error, (const void *)callermd->md_scb);
			wakeupself();
			return (error);
		}

		wakeupself();
	}

	SWITCHER_LOCK();
again:
	/*
	 * Wait for new caller.
	 */
	COLOCATION_DEBUG("waiting on %p",
	    (const void *)curthread->td_md.md_scb);
	error = msleep((const void *)curthread->td_md.md_scb,
	    &switcher_lock, PCATCH, "coaccept", 0);
	if (error != 0) {
		SWITCHER_UNLOCK();
		COLOCATION_DEBUG("msleep failed with error %d", error);
		return (error);
	}

	/*
	 * Both SCBs have likely been changed by cocall_slow(); refetch them.
	 */
	have_scb = colocation_fetch_scb(curthread, &scb);
	KASSERT(have_scb, ("%s: lost scb?", __func__));
	is_callee = colocation_fetch_caller_scb(curthread, &callerscb);
	if (!is_callee) {
		COLOCATION_DEBUG("woken up, but no caller yet");
		goto again;
	}
	SWITCHER_UNLOCK();

	/*
	 * Move data from caller to callee.
	 */
	error = copyinout(callerscb.scb_outbuf, inbuf,
	    MIN(inlen, callerscb.scb_outlen), true);
	if (error != 0) {
		COLOCATION_DEBUG("copyinout error %d", error);
		wakeupself();
		return (error);
	}

	/*
	 * Fill in the caller cookie.
	 */
	if (cookiep != NULL) {
		cookie = cheri_cleartag(scb.scb_caller_scb);
		error = copyoutcap(&cookie, cookiep, sizeof(cookie));
		if (error != 0) {
			COLOCATION_DEBUG("copyinout error %d", error);
			wakeupself();
			return (error);
		}
	}

	return (0);
}

int
sys_coaccept_slow(struct thread *td, struct coaccept_slow_args *uap)
{

	return (kern_coaccept_slow(uap->cookiep,
	    uap->outbuf, uap->outlen, uap->inbuf, uap->inlen));
}

#ifdef DDB
static void
db_print_scb(struct thread *td, struct switchercb *scb)
{

	if (cheri_getlen(scb->scb_caller_scb) == 0) {
		db_printf(       "    scb_caller_scb:    <errno %lu>\n",
		    cheri_getoffset(scb->scb_caller_scb));
	} else {
		db_print_cap(td, "    scb_caller_scb:    ", scb->scb_caller_scb);
	}
	db_print_cap(td, "    scb_callee_scb:    ", scb->scb_callee_scb);
	db_printf(       "    scb_td:            %p\n", scb->scb_td);
	db_printf(       "    scb_borrower_td:   %p\n", scb->scb_borrower_td);
	db_print_cap(td, "    scb_unsealcap:     ", scb->scb_unsealcap);
#ifdef __mips__
	db_print_cap(td, "    scb_tls:           ", scb->scb_tls);
	db_print_cap(td, "    scb_csp (c11):     ", scb->scb_csp);
	db_print_cap(td, "    scb_cra (c13):     ", scb->scb_cra);
	db_print_cap(td, "    scb_buf (c6):      ", scb->scb_buf);
	db_printf(       "    scb_buflen (a0):   %zd\n", scb->scb_buflen);
#else
	db_print_cap(td, "    scb_csp:           ", scb->scb_csp);
	db_print_cap(td, "    scb_cra:           ", scb->scb_cra);
	db_print_cap(td, "    scb_cookiep (ca2): ", scb->scb_cookiep);
	db_print_cap(td, "    scb_outbuf (ca3):  ", scb->scb_outbuf);
	db_printf(       "    scb_outlen (a4):   %zd\n", scb->scb_outlen);
	db_print_cap(td, "    scb_inbuf (ca5):   ", scb->scb_inbuf);
	db_printf(       "    scb_inlen (a6):    %zd\n", scb->scb_inlen);
#endif
	db_print_cap(td, "    scb_cookiep:       ", scb->scb_cookiep);
}

void
db_print_scb_td(struct thread *td)
{
	struct switchercb scb;
	bool have_scb;

	have_scb = colocation_fetch_scb(td, &scb);
	if (!have_scb)
		return;

	db_print_scb(td, &scb);
}

/*
 * Return PID owning the stack mapping the current userspace trapframe stack
 * pointer points to.  Simply put: returns the PID which belongs to the
 * userspace thread, which can - due to thread borrowing - be different from
 * the PID for the kernel thread.
 */
static pid_t
db_get_stack_pid(struct thread *td)
{
	vm_map_t map;
	vm_map_entry_t entry;
	vm_offset_t addr;
	boolean_t found;
	pid_t pid;

#if defined(__mips__)
	addr = __builtin_cheri_address_get(td->td_frame->csp);
//	db_printf("%s: td: %p; td_frame %p; csp: %#lp; csp addr: %lx\n",
//	    __func__, td, td->td_frame, td->td_frame->csp, (long)addr);
#elif defined(__riscv)
	addr = __builtin_cheri_address_get(td->td_frame->tf_sp);
//	db_printf("%s: td: %p; td_frame %p; tf_sp: %#lp; csp addr: %lx\n",
//	    __func__, td, td->td_frame,
//	    (void * __capability)td->td_frame->tf_sp, (long)addr);
#else
#error "what architecture is this?"
#endif

	map = &td->td_proc->p_vmspace->vm_map;
	vm_map_lock(map);
	found = vm_map_lookup_entry(map, addr, &entry);
	if (found)
		pid = entry->owner;
	else
		pid = -1;
	vm_map_unlock(map);

	return (pid);
}

DB_SHOW_COMMAND(scb, db_show_scb)
{
	struct switchercb scb;
	struct proc *p;
	struct thread *td, *borrowertd;
	int error;
	bool have_scb, shown_borrowertd;

	if (have_addr) {
		error = copyincap(___USER_CFROMPTR((const void *)addr, userspace_cap),
		    &scb, sizeof(scb));
		if (error != 0) {
			db_printf("%s: copyincap failed, error %d\n", __func__, error);
			return;
		}
		db_print_scb(NULL, &scb);
	} else {
		td = curthread;
		p = td->td_proc;
		have_scb = colocation_fetch_scb(td, &scb);
		if (!have_scb) {
			db_printf("    no scb\n");
			return;
		}
		db_printf(" switcher control block %p for curthread %p, pid %d (%s), stack owned by %d:\n",
		    (void *)td->td_md.md_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
		db_print_scb_td(td);

		borrowertd = scb.scb_borrower_td;
		shown_borrowertd = false;

		have_scb = colocation_fetch_caller_scb(td, &scb);
		if (have_scb) {
			if (borrowertd != scb.scb_td) {
				td = scb.scb_td;
				p = td->td_proc;
				db_printf(" caller's SCB %p owned by thread %p, pid %d (%s), stack owned by %d:\n",
				    (void *)td->td_md.md_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
			} else {
				td = borrowertd;
				p = td->td_proc;
				db_printf(" caller's SCB %p for borrowing thread %p, pid %d (%s), stack owned by %d:\n",
				    (void *)td->td_md.md_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
				shown_borrowertd = true;
			}
			db_print_scb(td, &scb);
		}

		td = curthread;
		have_scb = colocation_fetch_callee_scb(td, &scb);
		if (have_scb) {
			if (borrowertd != scb.scb_td) {
				td = scb.scb_td;
				p = td->td_proc;
				db_printf(" callee's SCB %p owned by thread %p, pid %d (%s), stack owned by %d:\n",
				    (void *)td->td_md.md_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
			} else {
				td = borrowertd;
				p = td->td_proc;
				db_printf(" callee's SCB %p for borrowing thread %p, pid %d (%s), stack owned by %d:\n",
				    (void *)td->td_md.md_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
				shown_borrowertd = true;
			}
			db_print_scb(td, &scb);
		}

		if (!shown_borrowertd && borrowertd != NULL) {
			td = borrowertd;
			p = td->td_proc;
			db_printf(" borrowing thread %p, pid %d (%s), stack owned by %d\n",
			    td, p->p_pid, p->p_comm, db_get_stack_pid(td));
		}
	}
}
#endif /* DDB */
