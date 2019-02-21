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

static void
colocation_startup(void)
{

	mtx_init(&switcher_lock, "switcher lock", NULL, MTX_DEF);
}
SYSINIT(colocation_startup, SI_SUB_CPU, SI_ORDER_FIRST, colocation_startup,
    NULL);

static bool
colocation_fetch_context(struct thread *td, struct switcher_context *scp)
{
	vaddr_t addr;
	int error;

	addr = td->td_md.md_switcher_context;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	error = copyincap(___USER_CFROMPTR((const void *)addr, userspace_cap),
	    &(*scp), sizeof(*scp));
#if 1
	KASSERT(error == 0, ("%s: copyincap from %p failed with error %d\n",
	    __func__, (void *)addr, error));
#else
	if (error != 0) {
		printf("%s: copyincap from %p failed with error %d\n",
		    __func__, (void *)addr, error);
		return (false);
	}
#endif

	if (scp->sc_borrower_td == NULL) {
		/*
		 * Nothing borrowed yet.
		 */
		return (false);
	}

	return (true);
}

static bool
colocation_fetch_peer_context(struct thread *td, struct switcher_context *scp)
{
	vaddr_t addr;
	int error;

	addr = td->td_md.md_switcher_context;
	if (addr == 0) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	error = copyincap(___USER_CFROMPTR((const void *)addr, userspace_cap),
	    &(*scp), sizeof(*scp));
	KASSERT(error == 0, ("%s: copyincap from %p failed with error %d\n",
	    __func__, (void *)addr, error));

	if (scp->sc_peer_context == NULL) {
		/*
		 * Not in cocall.
		 */
		return (false);
	}

	error = copyincap(scp->sc_peer_context, &(*scp), sizeof(*scp));
	KASSERT(error == 0,
	    ("%s: copyincap from peer %p failed with error %d\n",
	    __func__, (__cheri_fromcap void *)scp->sc_peer_context, error));

	return (true);
}

void
colocation_get_peer(struct thread *td, struct thread **peertdp)
{
	struct switcher_context sc;
	bool borrowing;

	borrowing = colocation_fetch_context(td, &sc);
	if (borrowing)
		*peertdp = sc.sc_borrower_td;
	else
		*peertdp = NULL;
}

void
colocation_thread_exit(struct thread *td)
{
	struct switcher_context sc, *peersc;
	vaddr_t addr;
	bool borrowing;
	int error;

	borrowing = colocation_fetch_context(td, &sc);
	if (!borrowing)
		return;

	addr = td->td_md.md_switcher_context;
	peersc = (__cheri_fromcap struct switcher_context *)sc.sc_peer_context;
	//printf("%s: terminating thread %p, peer context %p\n", __func__, td, peersc);

	/*
	 * Set sc_peer_context to a special "null" capability, so that cocall(2)
	 * can see the callee thread is dead.
	 */
	sc.sc_peer_context = cheri_capability_build_user_rwx(0, 0, 0, 0);
	sc.sc_td = NULL;
	sc.sc_borrower_td = NULL;

	error = copyoutcap(&sc, ___USER_CFROMPTR((void *)addr, userspace_cap), sizeof(sc));
	if (error != 0) {
		printf("%s: copyoutcap to %p failed with error %d\n",
		    __func__, (void *)addr, error);
		return;
	}

	if (peersc == NULL)
		return;

	error = copyincap(___USER_CFROMPTR((void *)peersc, userspace_cap), &sc, sizeof(sc));
	if (error != 0) {
		printf("%s: peer copyincap from %p failed with error %d\n",
		    __func__, (void *)peersc, error);
		return;
	}

	sc.sc_peer_context = NULL;
	sc.sc_borrower_td = NULL;

	error = copyoutcap(&sc, ___USER_CFROMPTR((void *)peersc, userspace_cap), sizeof(sc));
	if (error != 0) {
		printf("%s: peer copyoutcap to %p failed with error %d\n",
		    __func__, (void *)peersc, error);
		return;
	}
}

/*
 * Called from trap().
 */
void
colocation_unborrow(struct thread *td, struct trapframe **trapframep)
{
	struct switcher_context sc;
	struct thread *peertd;
	struct trapframe peertrapframe;
	struct syscall_args peersa;
	register_t peertpc;
	bool borrowing;

	borrowing = colocation_fetch_context(td, &sc);
	if (!borrowing)
		return;

	peertd = sc.sc_borrower_td;
	if (peertd == NULL) {
		/*
		 * Nothing borrowed yet.
		 */
		return;
	}

	KASSERT(peertd != td,
	    ("%s: peertd %p == td %p\n", __func__, peertd, td));

#if 0
	printf("%s: replacing current td %p, switcher_context %#lx, md_tls %p, md_tls_tcb_offset %zd, "
	    "with td %p, switcher_context %#lx, md_tls %p, md_tls_tcb_offset %zd\n", __func__,
	    td, td->td_md.md_switcher_context, (__cheri_fromcap void *)td->td_md.md_tls, td->td_md.md_tls_tcb_offset,
	    peertd, peertd->td_md.md_switcher_context, (__cheri_fromcap void *)peertd->td_md.md_tls, peertd->td_md.md_tls_tcb_offset);
#endif

	/*
	 * Assign our trapframe (userspace context) to the thread waiting
	 * in copark(2) and wake it up; it'll return to userspace with ERESTART
	 * and then bounce back.
	 */
	KASSERT(td->td_frame == &td->td_pcb->pcb_regs,
	    ("%s: td->td_frame %p != &td->td_pcb->pcb_regs %p, td %p",
	    __func__, td->td_frame, &td->td_pcb->pcb_regs, td));
	KASSERT(peertd->td_frame == &peertd->td_pcb->pcb_regs,
	    ("%s: peertd->td_frame %p != &peertd->td_pcb->pcb_regs %p, peertd %p",
	    __func__, peertd->td_frame, &peertd->td_pcb->pcb_regs, peertd));

	peersa = peertd->td_sa;
	cheri_memcpy(&peertrapframe, peertd->td_sa.trapframe, sizeof(struct trapframe));
	peertpc = peertd->td_pcb->pcb_tpc;

	peertd->td_sa = td->td_sa;
	cheri_memcpy(peertd->td_frame, *trapframep, sizeof(struct trapframe));
	peertd->td_pcb->pcb_tpc = td->td_pcb->pcb_tpc;

	td->td_sa = peersa;
	cheri_memcpy(td->td_frame, &peertrapframe, sizeof(struct trapframe));
	td->td_pcb->pcb_tpc = peertpc;

	*trapframep = td->td_frame;

	wakeup(&peertd->td_md.md_switcher_context);

	/*
	 * Continue as usual, but calling copark(2) instead of whatever
	 * syscall it was.
	 */
	KASSERT(td->td_sa.code == SYS_copark,
	    ("%s: td_sa.code %d != %d\n", __func__, td->td_sa.code, SYS_copark));
}

static int
cosetup(struct thread *td)
{
	struct switcher_context sc;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_offset_t addr;
	boolean_t found;
	int error;

	KASSERT(td->td_md.md_switcher_context == 0, ("%s: already initialized\n", __func__));

	map = &td->td_proc->p_vmspace->vm_map;

	/*
	 * XXX: Race between this and setting the owner.  If we moved the lock
	 * 	earlier, we'd die on:
	 *
	 * 	panic: _sx_xlock_hard: recursed on non-recursive sx vm map (user) @ /usr/home/en322/cheri/cheribsd/sys/vm/vm_map.c:1746
	 */
	error = vm_mmap_object(map, &addr, 0, PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL,
	    MAP_PRIVATE | MAP_ANON, NULL, 0, FALSE, td);
	if (error != 0) {
		printf("%s: vm_mmap_object() failed with error %d\n",
		    __func__, error);
		return (error);
	}
	td->td_md.md_switcher_context = addr;

	vm_map_lock(map);
	found = vm_map_lookup_entry(map, addr, &entry);
	KASSERT(found == TRUE,
	    ("%s: vm_map_lookup_entry() returned false\n", __func__));
	entry->owner = 0;
	vm_map_unlock(map);

	//printf("%s: context at %p, td %p\n", __func__, (void *)addr, td);
	sc.sc_unsealcap = switcher_sealcap2;
	sc.sc_td = td;
	sc.sc_borrower_td = NULL;
	sc.sc_peer_context = NULL;

	error = copyoutcap(&sc,
	    ___USER_CFROMPTR((void *)addr, userspace_cap), sizeof(sc));
	KASSERT(error == 0,
	    ("%s: copyoutcap() failed with error %d\n", __func__, error));

	return (0);
}

int
sys_cosetup(struct thread *td, struct cosetup_args *uap)
{

	return (kern_cosetup(td, uap->what,
	    __USER_CAP(uap->code, sizeof(void * __capability)),
	    __USER_CAP(uap->data, sizeof(void * __capability))));
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

	if (td->td_md.md_switcher_context == 0) {
		error = cosetup(td);
		if (error != 0) {
			printf("%s: cosetup() failed with error %d\n",
			    __func__, error);
			return (error);
		}
	}

	addr = td->td_md.md_switcher_context;

	switch (what) {
	case COSETUP_COCALL:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cocall_base,
		    td->td_proc->p_sysent->sv_cocall_len, 0);
		codecap = cheri_seal(codecap, switcher_sealcap);
		error = copyoutcap(&codecap, codep, sizeof(codecap));
		if (error != 0)
			return (error);

		datacap = cheri_capability_build_user_rwx(CHERI_CAP_USER_DATA_PERMS,
		    addr, PAGE_SIZE, 0);
		datacap = cheri_seal(datacap, switcher_sealcap);
		error = copyoutcap(&datacap, datap, sizeof(datacap));
		return (0);

	case COSETUP_COACCEPT:
		codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_coaccept_base,
		    td->td_proc->p_sysent->sv_coaccept_len, 0);
		codecap = cheri_seal(codecap, switcher_sealcap);
		error = copyoutcap(&codecap, codep, sizeof(codecap));
		if (error != 0)
			return (error);

		datacap = cheri_capability_build_user_rwx(CHERI_CAP_USER_DATA_PERMS,
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

	return (kern_coregister(td, __USER_CAP_STR(uap->name),
	    __USER_CAP(uap->cap, sizeof(void * __capability))));
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

	error = copyinstr_c(namep, name, sizeof(name), NULL);
	if (error != 0)
		return (error);

	if (strlen(name) == 0)
		return (EINVAL);

	if (strlen(name) >= PATH_MAX)
		return (ENAMETOOLONG);

	if (td->td_md.md_switcher_context == 0) {
		error = cosetup(td);
		if (error != 0)
			return (error);
	}

	addr = td->td_md.md_switcher_context;

	vm_map_lock(&vmspace->vm_map);
	LIST_FOREACH(con, &vmspace->vm_conames, c_next) {
		if (strcmp(name, con->c_name) == 0) {
			vm_map_unlock(&vmspace->vm_map);
			return (EEXIST);
		}
	}

	cap = cheri_capability_build_user_rwx(CHERI_CAP_USER_DATA_PERMS,
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
	con->c_value = cap;
	LIST_INSERT_HEAD(&vmspace->vm_conames, con, c_next);
	vm_map_unlock(&vmspace->vm_map);

	return (0);
}

int
sys_colookup(struct thread *td, struct colookup_args *uap)
{

	return (kern_colookup(td, __USER_CAP_STR(uap->name),
	    __USER_CAP(uap->cap, sizeof(void * __capability))));
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

	error = copyinstr_c(namep, name, sizeof(name), NULL);
	if (error != 0)
		return (error);

	vm_map_lock(&vmspace->vm_map);
	LIST_FOREACH(con, &vmspace->vm_conames, c_next) {
		if (strcmp(name, con->c_name) == 0)
			break;
	}

	if (con == NULL) {
		vm_map_unlock(&vmspace->vm_map);
		return (ESRCH);
	}

	error = copyoutcap(&con->c_value, capp, sizeof(con->c_value));
	vm_map_unlock(&vmspace->vm_map);
	return (error);
}

int
sys_cogetpid(struct thread *td, struct cogetpid_args *uap)
{

	return (kern_cogetpid(td, __USER_CAP(uap->pidp, sizeof(pid_t))));
}

int
kern_cogetpid(struct thread *td, pid_t * __capability pidp)
{
	struct switcher_context sc;
	bool is_callee;
	pid_t pid;
	int error;

	is_callee = colocation_fetch_peer_context(td, &sc);
	if (!is_callee)
		return (ESRCH);

	pid = sc.sc_td->td_proc->p_pid;
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

	//printf("%s: go, td %p!\n", __func__, td);

	mtx_lock(&switcher_lock);
	error = msleep(&td->td_md.md_switcher_context, &switcher_lock,
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
kern_colocate(struct thread *td, pid_t pid)
{

	return (EDOOFUS);
}
	
int
sys_colocate(struct thread *td, struct colocate_args *uap)
{

	return (kern_colocate(td, uap->pid));
}

