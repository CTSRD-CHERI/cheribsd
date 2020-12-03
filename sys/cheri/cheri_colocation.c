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

struct mtx		switcher_lock;

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
#endif

#define	COLOCATION_DEBUG(X, ...)					\
	do {								\
		if (colocation_debug > 0)				\
			printf("%s: " X "\n", __func__, ## __VA_ARGS__);\
	} while (0)

static void
colocation_startup(void)
{

	mtx_init(&switcher_lock, "switcher lock", NULL, MTX_DEF);
}
SYSINIT(colocation_startup, SI_SUB_CPU, SI_ORDER_FIRST, colocation_startup,
    NULL);

void
colocation_cleanup(struct thread *td)
{
	td->td_md.md_scb = 0;

	/*
	 * XXX: This should be only neccessary with INVARIANTS.
	 */
	memset(&td->td_md.md_slow_cv, 0, sizeof(struct cv));
	memset(&td->td_md.md_slow_lock, 0, sizeof(struct sx));
	td->td_md.md_slow_caller_td = NULL;
	td->td_md.md_slow_buf = NULL;
	td->td_md.md_slow_len = 0;
	td->td_md.md_slow_accepting = false;
}

static bool
colocation_fetch_scb(struct thread *td, struct switchercb *scbp)
{
	vaddr_t addr;
	int error;

	addr = td->td_md.md_scb;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	error = copyincap(___USER_CFROMPTR((const void *)addr, userspace_cap),
	    &(*scbp), sizeof(*scbp));
	KASSERT(error == 0, ("%s: copyincap from %p failed with error %d\n",
	    __func__, (void *)addr, error));

	return (true);
}

static bool
colocation_fetch_caller_scb(struct thread *td, struct switchercb *scbp)
{
	vaddr_t addr;
	int error;

	addr = td->td_md.md_scb;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	error = copyincap(___USER_CFROMPTR((const void *)addr, userspace_cap),
	    &(*scbp), sizeof(*scbp));
	KASSERT(error == 0, ("%s: copyincap from %p failed with error %d\n",
	    __func__, (void *)addr, error));

	if (cheri_gettag(scbp->scb_caller_scb) == 0 ||
	    cheri_getlen(scbp->scb_caller_scb) == 0) {
		/*
		 * Not in cocall.
		 */
		return (false);
	}

	error = copyincap(scbp->scb_caller_scb, &(*scbp), sizeof(*scbp));
	KASSERT(error == 0,
	    ("%s: copyincap from peer %p failed with error %d\n",
	    __func__, (__cheri_fromcap void *)scbp->scb_caller_scb, error));

	return (true);
}

static bool
colocation_fetch_callee_scb(struct thread *td, struct switchercb *scbp)
{
	vaddr_t addr;
	int error;

	addr = td->td_md.md_scb;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	error = copyincap(___USER_CFROMPTR((const void *)addr, userspace_cap),
	    &(*scbp), sizeof(*scbp));
	KASSERT(error == 0, ("%s: copyincap from %p failed with error %d\n",
	    __func__, (void *)addr, error));

	if (cheri_gettag(scbp->scb_callee_scb) == 0 ||
	    cheri_getlen(scbp->scb_callee_scb) == 0) {
		/*
		 * Not in cocall.
		 */
		return (false);
	}

	error = copyincap(scbp->scb_callee_scb, &(*scbp), sizeof(*scbp));
	KASSERT(error == 0,
	    ("%s: copyincap from peer %p failed with error %d\n",
	    __func__, (__cheri_fromcap void *)scbp->scb_callee_scb, error));

	return (true);
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

	if (cheri_gettag(scb.scb_caller_scb) != 0 &&
	    cheri_getlen(scb.scb_caller_scb) > 0)
		*peertdp = scb.scb_borrower_td;
	else
		*peertdp = NULL;
}

void
colocation_thread_exit(struct thread *td)
{
	struct vmspace *vmspace;
	struct coname *con, *con_temp;

	struct mdthread *md, *callermd;
	struct switchercb scb, *peerscb;
	vaddr_t addr;
	bool have_scb;
	int error;

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
	sx_xlock(&md->md_slow_lock);
	md->md_slow_accepting = false;
	sx_xunlock(&md->md_slow_lock);

	/*
	 * Wake up any thread waiting on cocall_slow(2).
	 */
	if (md->md_slow_caller_td != NULL) {
		COLOCATION_DEBUG("waking up slow cocaller %p", md->md_slow_caller_td);
		callermd = &md->md_slow_caller_td->td_md;
		cv_signal(&callermd->md_slow_cv);
	}

	peerscb = (__cheri_fromcap struct switchercb *)scb.scb_caller_scb;
	COLOCATION_DEBUG("terminating thread %p, scb %p, peer scb %p",
	    td, (void *)td->td_md.md_scb, peerscb);

	/*
	 * Set scb_caller_scb to a special "null" capability, so that cocall(2)
	 * can see the callee thread is dead.
	 */
	scb.scb_caller_scb = cheri_capability_build_user_data(0, 0, 0, EPIPE);
	scb.scb_td = NULL;
	scb.scb_borrower_td = NULL;

	addr = td->td_md.md_scb;
	td->td_md.md_scb = 0;
	error = copyoutcap(&scb, ___USER_CFROMPTR((void *)addr, userspace_cap), sizeof(scb));
	if (error != 0) {
		COLOCATION_DEBUG("copyoutcap to %p failed with error %d",
		    (void *)addr, error);
		return;
	}

	if (peerscb == NULL)
		return;

	error = copyincap(___USER_CFROMPTR((void *)peerscb, userspace_cap), &scb, sizeof(scb));
	if (error != 0) {
		COLOCATION_DEBUG("peer copyincap from %p failed with error %d",
		    (void *)peerscb, error);
		return;
	}

	scb.scb_caller_scb = NULL;
	scb.scb_borrower_td = NULL;

	error = copyoutcap(&scb, ___USER_CFROMPTR((void *)peerscb, userspace_cap), sizeof(scb));
	if (error != 0) {
		COLOCATION_DEBUG("peer copyoutcap to %p failed with error %d",
		    (void *)peerscb, error);
		return;
	}
}

/*
 * Assign our trapframe (userspace context) to the thread waiting
 * in copark(2) and wake it up; it'll return to userspace with ERESTART
 * and then bounce back.
 *
 * Called from trap().
 */
void
colocation_unborrow(struct thread *td, struct trapframe *trapframe)
{
	struct switchercb scb;
	struct thread *peertd;
	struct trapframe peertrapframe;
#ifdef __mips__
	trapf_pc_t peertpc;
#endif
	bool have_scb;

	have_scb = colocation_fetch_scb(td, &scb);
	if (!have_scb)
		return;

	peertd = scb.scb_borrower_td;
	if (peertd == NULL) {
		/*
		 * Nothing borrowed yet.
		 */
		return;
	}

	KASSERT(peertd != td,
	    ("%s: peertd %p == td %p\n", __func__, peertd, td));
	KASSERT(trapframe == td->td_frame,
	    ("%s: %p != %p", __func__, trapframe, td->td_frame));

#ifdef __mips__
	COLOCATION_DEBUG("replacing current td %p, pid %d (%s), switchercb %#lx, "
	    "md_tls %p, md_tls_tcb_offset %zd, "
	    "with td %p, pid %d (%s), switchercb %#lx, "
	    "md_tls %p, md_tls_tcb_offset %zd",
	    td, td->td_proc->p_pid, td->td_proc->p_comm, td->td_md.md_scb,
	    (__cheri_fromcap void *)td->td_md.md_tls, td->td_proc->p_md.md_tls_tcb_offset,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm, peertd->td_md.md_scb,
	    (__cheri_fromcap void *)peertd->td_md.md_tls, peertd->td_proc->p_md.md_tls_tcb_offset);
#else
	COLOCATION_DEBUG("replacing current td %p, pid %d (%s), switchercb %#lx, "
	    "with td %p, pid %d (%s), switchercb %#lx",
	    td, td->td_proc->p_pid, td->td_proc->p_comm, td->td_md.md_scb,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm, peertd->td_md.md_scb);
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
#endif
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
	int error;

	addr = td->td_md.md_scb;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return;
	}

	error = copyincap(___USER_CFROMPTR((const void *)addr, userspace_cap), &scb, sizeof(scb));
	KASSERT(error == 0, ("%s: copyincap from %p failed with error %d\n", __func__, (void *)addr, error));

	COLOCATION_DEBUG("changing TLS from %p to %p",
	    (__cheri_fromcap void *)scb.scb_tls,
	    (__cheri_fromcap void *)((char * __capability)td->td_md.md_tls + td->td_proc->p_md.md_tls_tcb_offset));
	scb.scb_tls = (char * __capability)td->td_md.md_tls + td->td_proc->p_md.md_tls_tcb_offset;

	error = copyoutcap(&scb, ___USER_CFROMPTR((void *)addr, userspace_cap), sizeof(scb));
	KASSERT(error == 0, ("%s: copyoutcap from %p failed with error %d\n", __func__, (void *)addr, error));
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
	int error, rv;

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
#endif

	error = copyoutcap(&scb,
	    ___USER_CFROMPTR((void *)addr, userspace_cap), sizeof(scb));
	KASSERT(error == 0,
	    ("%s: copyoutcap() failed with error %d\n", __func__, error));

	/*
	 * Stuff neccessary for cocall_slow(2)/coaccept_slow(2).
	 */
	cv_init(&td->td_md.md_slow_cv, "slowcv");
	sx_init(&td->td_md.md_slow_lock, "slowlock");
	td->td_md.md_slow_caller_td = NULL;
	td->td_md.md_slow_buf = NULL;
	td->td_md.md_slow_len = 0;
	td->td_md.md_slow_accepting = false;

	return (0);
}

int
sys_cosetup(struct thread *td, struct cosetup_args *uap)
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

	case COSETUP_COACCEPT:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_coaccept_base,
		    td->td_proc->p_sysent->sv_coaccept_len, 0);
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

	default:
		return (EINVAL);
	}
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

	error = copyinstr(namep, name, sizeof(name), NULL);
	if (error != 0)
		return (error);

	if (strlen(name) == 0)
		return (EINVAL);

	if (strlen(name) >= PATH_MAX)
		return (ENAMETOOLONG);

	if (td->td_md.md_scb == 0) {
		error = setup_scb(td);
		if (error != 0)
			return (error);
	}

	addr = td->td_md.md_scb;

	vm_map_lock(&vmspace->vm_map);
	LIST_FOREACH(con, &vmspace->vm_conames, c_next) {
		if (strcmp(name, con->c_name) == 0) {
			vm_map_unlock(&vmspace->vm_map);
			return (EEXIST);
		}
	}

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

	con = malloc(sizeof(struct coname), M_TEMP, M_WAITOK);
	con->c_name = strdup(name, M_TEMP);
	con->c_td = curthread;
	con->c_value = cap;
	LIST_INSERT_HEAD(&vmspace->vm_conames, con, c_next);
	vm_map_unlock(&vmspace->vm_map);

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

	mtx_lock(&switcher_lock);
	error = msleep(&td->td_md.md_scb, &switcher_lock,
	    PPAUSE | PCATCH, "copark", 0);
	mtx_unlock(&switcher_lock);

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
kern_cocall_slow(void * __capability code, void * __capability data,
    void * __capability target, void * __capability buf, size_t len)
{
	struct mdthread *md, *calleemd;
	struct thread *calleetd;
	struct coname *con;
	int error;

	md = &curthread->td_md;

	/*
	 * Copy from caller into the kernel buffer.
	 */
	if (buf == NULL) {
		if (len != 0) {
			COLOCATION_DEBUG("buf == NULL, but len != 0, returning EINVAL");
			return (EINVAL);
		}

		md->md_slow_len = 0;
		md->md_slow_buf = NULL;
	} else {
		if (len == 0) {
			COLOCATION_DEBUG("buf != NULL, but len == 0, returning EINVAL");
			return (EINVAL);
		}

		if (len > MAXBSIZE) {
			COLOCATION_DEBUG("len %zd > %d, returning EMSGSIZE", len, MAXBSIZE);
			return (EMSGSIZE);
		}

		md->md_slow_len = len;
		md->md_slow_buf = malloc(len, M_TEMP, M_WAITOK);

		error = copyin(buf, md->md_slow_buf, len);
		if (error != 0) {
			COLOCATION_DEBUG("copyin failed with error %d", error);
			goto out;
		}
	}

	/*
	 * Find the callee (coaccepting) thread.
	 */
	calleetd = NULL;
	LIST_FOREACH(con, &curthread->td_proc->p_vmspace->vm_conames, c_next) {
		if (con->c_value == target) {
			calleetd = con->c_td;
			break;
		}
	}

	if (calleetd == NULL) {
		COLOCATION_DEBUG("target thread not found, returning EINVAL");
		error = EINVAL;
		goto out;
	}

	calleemd = &calleetd->td_md;
	sx_xlock(&calleemd->md_slow_lock);

	if (!calleemd->md_slow_accepting) {
		sx_xunlock(&calleemd->md_slow_lock);
		COLOCATION_DEBUG("target not in coaccept_slow(2), returning EINVAL");
		error = EINVAL;
		goto out;
	}

	/*
	 * Wake up the callee and wait for them to complete.
	 */
	calleemd->md_slow_caller_td = curthread;
	cv_signal(&calleemd->md_slow_cv);
	error = cv_wait_sig(&md->md_slow_cv, &calleemd->md_slow_lock);
	if (error != 0) {
		calleemd->md_slow_caller_td = NULL;
		sx_xunlock(&calleemd->md_slow_lock);
		COLOCATION_DEBUG("cv_wait_sig failed with error %d", error);
		error = EINVAL;
		goto out;
	}

	/*
	 * Copy stuff out into caller's buffer, if there is anything.
	 */
	if (buf != NULL) {
		if (len > md->md_slow_len)
			len = md->md_slow_len;
		if (len > 0) {
			error = copyout(md->md_slow_buf, buf, len);
			if (error != 0)
				COLOCATION_DEBUG("copyout failed with error %d", error);
		}
	}

	calleemd->md_slow_caller_td = NULL;
	sx_xunlock(&calleemd->md_slow_lock);
out:

	free(md->md_slow_buf, M_TEMP);
	md->md_slow_buf = NULL;
	md->md_slow_len = 0;

	return (error);
}

int
sys_cocall_slow(struct thread *td, struct cocall_slow_args *uap)
{

	return (kern_cocall_slow(uap->code, uap->data,
	    uap->target, uap->buf, uap->len));
}

int
kern_coaccept_slow(void * __capability code, void * __capability data,
    void * __capability * __capability cookiep, void * __capability buf, size_t len)
{
	struct mdthread *md, *callermd;
	size_t minlen;
	int error;

	md = &curthread->td_md;

	if (buf == NULL) {
		if (len != 0) {
			COLOCATION_DEBUG("buf != NULL, but len == 0, returning EINVAL");
			return (EINVAL);
		}
	} else {
		if (len == 0) {
			COLOCATION_DEBUG("buf != NULL, but len == 0, returning EINVAL");
			return (EINVAL);
		}

		if (len > MAXBSIZE) {
			COLOCATION_DEBUG("len %zd > %d, returning EMSGSIZE", len, MAXBSIZE);
			return (EMSGSIZE);
		}
	}

	/*
	 * If there's a caller waiting for us, get them their data
	 * and wake them up.
	 */
	if (md->md_slow_caller_td != NULL) {
		callermd = &md->md_slow_caller_td->td_md;

		if (buf != NULL) {
			minlen = MIN(len, callermd->md_slow_len);
			if (minlen > 0) {
				error = copyin(buf, callermd->md_slow_buf, minlen);
				if (error != 0) {
					COLOCATION_DEBUG("copyin failed with error %d", error);
					return (error);
				}
			}
		}

		cv_signal(&callermd->md_slow_cv);
	}

	/*
	 * NB: This is not supposed to be cleared until the thread exits.
	 */
	md->md_slow_accepting = true;

	/*
	 * Wait for a new caller.
	 */
	sx_xlock(&md->md_slow_lock);
	error = cv_wait_sig(&md->md_slow_cv, &md->md_slow_lock);
	sx_xunlock(&md->md_slow_lock); // XXX
	if (error != 0) {
		COLOCATION_DEBUG("cv_wait_sig failed with error %d", error);
		return (error);
	}

	callermd = &md->md_slow_caller_td->td_md;

	/*
	 * Copy stuff out into the userspace buffer and return to the callee.
	 */
	if (buf != NULL) {
		minlen = MIN(len, callermd->md_slow_len);
		if (minlen > 0) {
			error = copyout(callermd->md_slow_buf, buf, len);
			if (error != 0)
				COLOCATION_DEBUG("copyout failed with error %d", error);
		}
	}

	return (error);
}

int
sys_coaccept_slow(struct thread *td, struct coaccept_slow_args *uap)
{

	return (kern_coaccept_slow(uap->code, uap->data,
	    uap->cookiep, uap->buf, uap->len));
}

#ifdef DDB
static void
db_print_scb(struct switchercb *scb)
{

	if (cheri_getlen(scb->scb_caller_scb) == 0) {
		db_printf("    scb_caller_scb:    <errno %lu>\n",
		    cheri_getoffset(scb->scb_caller_scb));
	} else {
		db_printf("    scb_caller_scb:    %#lp\n", scb->scb_caller_scb);
	}
	db_printf("    scb_callee_scb:    %#lp\n", scb->scb_callee_scb);
	db_printf("    scb_td:            %p\n", scb->scb_td);
	db_printf("    scb_borrower_td:   %p\n", scb->scb_borrower_td);
#ifdef __mips__
	db_printf("    scb_tls:           %#lp\n", scb->scb_tls);
	db_printf("    scb_csp (c11):     %#lp\n", scb->scb_csp);
	db_printf("    scb_cra (c13):     %#lp\n", scb->scb_cra);
	db_printf("    scb_buf (c6):      %#lp\n", scb->scb_buf);
	db_printf("    scb_buflen (a0):   %zd\n", scb->scb_buflen);
	db_printf("    scb_cookiep:       %#lp\n", scb->scb_cookiep);
#else
	db_printf("    scb_csp:           %#lp\n", scb->scb_csp);
	db_printf("    scb_cra:           %#lp\n", scb->scb_cra);
	db_printf("    scb_cookiep (ca2): %#lp\n", scb->scb_cookiep);
	db_printf("    scb_buf (ca3):     %#lp\n", scb->scb_buf);
	db_printf("    scb_buflen (a4):   %zd\n", scb->scb_buflen);
#endif
}

void
db_print_scb_td(struct thread *td)
{
	struct switchercb scb;
	bool have_scb;

	have_scb = colocation_fetch_scb(td, &scb);
	if (!have_scb)
		return;

	db_print_scb(&scb);
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
	db_printf("%s: td: %p; td_frame %p; csp: %#lp; csp addr: %lx\n",
	    __func__, td, td->td_frame, td->td_frame->csp, (long)addr);
#elif defined(__riscv)
	addr = __builtin_cheri_address_get(td->td_frame->tf_sp);
	db_printf("%s: td: %p; td_frame %p; tf_sp: %#lp; csp addr: %lx\n",
	    __func__, td, td->td_frame,
	    (void * __capability)td->td_frame->tf_sp, (long)addr);
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
		db_print_scb(&scb);
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
			db_print_scb(&scb);
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
			db_print_scb(&scb);
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
