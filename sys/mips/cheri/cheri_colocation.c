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

/*
 * Capability used to seal capability pairs returned by cosetup(2).
 */
void * __capability	switcher_sealcap;

/*
 * Capability used to seal capabilities returned by coregister(2)/colookup(2).
 */
void * __capability	switcher_sealcap2;

/*
 * For now, all we do is declare what we support, as most initialisation took
 * place in the MIPS machine-dependent assembly.  CHERI doesn't need a lot of
 * actual boot-time initialisation.
 */
static void
colocation_startup(void)
{

	cheri_capability_set(&switcher_sealcap, CHERI_SEALCAP_SWITCHER_PERMS,
	    CHERI_SEALCAP_SWITCHER_BASE, CHERI_SEALCAP_SWITCHER_LENGTH,
	    CHERI_SEALCAP_SWITCHER_OFFSET);

	cheri_capability_set(&switcher_sealcap2, CHERI_SEALCAP_SWITCHER2_PERMS,
	    CHERI_SEALCAP_SWITCHER2_BASE, CHERI_SEALCAP_SWITCHER2_LENGTH,
	    CHERI_SEALCAP_SWITCHER2_OFFSET);

}
SYSINIT(colocation_startup, SI_SUB_CPU, SI_ORDER_FIRST, colocation_startup,
    NULL);

static int
cosetup(struct thread *td)
{
	struct switcher_context sc;
	vm_map_t map;
	vm_map_entry_t entry;
	vaddr_t addr;
	boolean_t found;
	int error;

	KASSERT(td->td_md.md_switcher_context == 0, ("%s: already initialized\n", __func__));

	/*
	 * XXX: Race between this and setting the owner.
	 */
	error = kern_mmap(td, 0, 0, PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE, MAP_ANON, -1, 0);
	if (error != 0) {
		printf("%s: kern_mmap() failed with error %d\n", __func__, error);
		return (error);
	}

	addr = td->td_retval[0];
	td->td_md.md_switcher_context = addr;
	td->td_retval[0] = 0;

	map = &td->td_proc->p_vmspace->vm_map;
	vm_map_lock(map);
	found = vm_map_lookup_entry(map, addr, &entry);
	KASSERT(found == TRUE, ("%s: vm_map_lookup_entry returned false\n", __func__));

	entry->owner = 0;
	vm_map_unlock(map);

	printf("%s: context at %p, td %p\n", __func__, (void *)addr, td);
	sc.sc_unsealcap = switcher_sealcap2;
	sc.sc_td = td;
	sc.sc_borrower_td = NULL;
	sc.sc_peer_context = NULL;

	error = copyoutcap(&sc, (void *)addr, sizeof(sc));
	KASSERT(error == 0, ("%s: copyout failed with error %d\n", __func__, error));

	return (0);
}

int
sys_cosetup(struct thread *td, struct cosetup_args *uap)
{
	void * __capability codecap;
	void * __capability datacap;
	vaddr_t addr;
	int error;

	if (td->td_md.md_switcher_context == 0) {
		error = cosetup(td);
		if (error != 0)
			return (error);
	}

	addr = td->td_md.md_switcher_context;

	switch (uap->what) {
	case COSETUP_COCALL:
		cheri_capability_set(&codecap, CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_cocall_base,
		    td->td_proc->p_sysent->sv_cocall_len, 0);
		codecap = cheri_seal(codecap, switcher_sealcap);
		error = copyoutcap(&codecap, uap->code, sizeof(codecap));
		if (error != 0)
			return (error);

		cheri_capability_set(&datacap,
		    CHERI_CAP_USER_DATA_PERMS, addr, PAGE_SIZE, 0);
		datacap = cheri_seal(datacap, switcher_sealcap);
		error = copyoutcap(&datacap, uap->data, sizeof(datacap));
		return (0);

	case COSETUP_COACCEPT:
		cheri_capability_set(&codecap, CHERI_CAP_USER_CODE_PERMS,
		    td->td_proc->p_sysent->sv_coaccept_base,
		    td->td_proc->p_sysent->sv_coaccept_len, 0);
		codecap = cheri_seal(codecap, switcher_sealcap);
		error = copyoutcap(&codecap, uap->code, sizeof(codecap));
		if (error != 0)
			return (error);

		cheri_capability_set(&datacap,
		    CHERI_CAP_USER_DATA_PERMS, addr, PAGE_SIZE, 0);
		datacap = cheri_seal(datacap, switcher_sealcap);
		error = copyoutcap(&datacap, uap->data, sizeof(datacap));
		return (0);

	default:
		return (EINVAL);
	}
}

int
sys_coregister(struct thread *td, struct coregister_args *uap)
{
	struct vmspace *vmspace;
	struct coname *con;
	char name[PATH_MAX];
	void * __capability cap;
	vaddr_t addr;
	int error;

	vmspace = td->td_proc->p_vmspace;

	error = copyinstr(uap->name, name, sizeof(name), NULL);
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

	cheri_capability_set(&cap, CHERI_CAP_USER_DATA_PERMS, addr, PAGE_SIZE, 0);
	cap = cheri_seal(cap, switcher_sealcap2);

	if (uap->cap != NULL) {
		error = copyoutcap(&cap, uap->cap, sizeof(cap));
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
	struct vmspace *vmspace;
	const struct coname *con;
	char name[PATH_MAX];
	int error;

	vmspace = td->td_proc->p_vmspace;

	error = copyinstr(uap->name, name, sizeof(name), NULL);
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

	error = copyoutcap(&con->c_value, uap->cap, sizeof(con->c_value));
	vm_map_unlock(&vmspace->vm_map);
	return (error);
}

int
sys_copark(struct thread *td, struct copark_args *uap)
{
	int error;

	//printf("%s: go, td %p!\n", __func__, td);

	mtx_lock(&Giant);
	error = msleep(&td->td_md.md_switcher_context, &Giant, PPAUSE | PCATCH, "copark", 0);
	mtx_unlock(&Giant);

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
