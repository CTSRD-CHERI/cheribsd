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
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/sx.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/unistd.h>

#if __has_feature(capabilities)

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

/*
 * Capability used to seal capability pairs returned by cosetup(2).
 */
void * __capability	switcher_sealcap = (void * __capability)-1;

/*
 * Capability used to seal capabilities returned by coregister(2)/colookup(2).
 */
void * __capability	switcher_sealcap2 = (void * __capability)-1;

/*
 * Capability used to seal capabilities returned by capfromfd(2).
 */
void * __capability	capfd_sealcap = (void * __capability)-1;

struct sx		switcher_lock;

#define	SWITCHER_LOCK()		sx_xlock(&switcher_lock)
#define	SWITCHER_UNLOCK()	sx_xunlock(&switcher_lock)

static int colocation_debug;
SYSCTL_INT(_debug, OID_AUTO, colocation_debug, CTLFLAG_RWTUN,
    &colocation_debug, 0, "Enable process colocation debugging");
static int counregister_on_exit = 1;
SYSCTL_INT(_debug, OID_AUTO, counregister_on_exit, CTLFLAG_RWTUN,
    &counregister_on_exit, 0, "Remove dead conames on thread exit");

bool allow_colookup = true;
SYSCTL_BOOL(_security_bsd, OID_AUTO, allow_colookup, CTLFLAG_RWTUN,
    &allow_colookup, 0,
    "Deny colookup(2) use by returning ENOSYS");

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
	td->td_scb = NULL;
}

static void
colocation_copyin_scb(const struct switchercb * __capability cap,
    struct switchercb *scbp)
{
	int error __diagused;

	KASSERT(cap != NULL, ("%s: NULL addr", __func__));

	error = copyincap(cap, scbp, sizeof(*scbp));
	KASSERT(error == 0, ("%s: copyincap from %#lp failed with error %d\n",
	    __func__, cap, error));
}

static bool
colocation_fetch_scb(struct thread *td, struct switchercb *scbp)
{
	if (td->td_scb == NULL) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	colocation_copyin_scb(td->td_scb, scbp);

	return (true);
}

static void
colocation_copyout_scb(void * __capability cap, const struct switchercb *scbp)
{
	int error __diagused;

	KASSERT(cap != NULL, ("%s: NULL addr", __func__));

	error = copyoutcap(scbp, cap, sizeof(*scbp));
	KASSERT(error == 0, ("%s: copyoutcap to %#lp failed with error %d",
	    __func__, cap, error));
}

static void
colocation_store_scb(struct thread *td, struct switchercb *scbp)
{

	colocation_copyout_scb(td->td_scb, scbp);
}

static void
colocation_store_caller_scb(struct switchercb * __capability user_scbp,
    struct switchercb * __capability caller_scb)
{
	int error __diagused;

	error = sucap(&user_scbp->scb_caller_scb, (intcap_t)caller_scb);
	KASSERT(error == 0, ("%s: sucap to %#lp failed with error %d",
	    __func__, user_scbp, error));
}

static bool
colocation_fetch_caller_scb(struct thread *td, struct switchercb *scbp)
{
	if (td->td_scb == NULL) {
		/*
		 * We've never called cosetup(2).
		 */
		COLOCATION_DEBUG("never called cosetup");
		return (false);
	}

	colocation_copyin_scb(td->td_scb, scbp);

	if (cheri_gettag(scbp->scb_caller_scb) == 0 ||
	    cheri_getlen(scbp->scb_caller_scb) == 0) {
		/*
		 * Not in cocall.
		 */
		COLOCATION_DEBUG("not in cocall (caller_scb %#lp tag %d, len %zd)",
		   scbp->scb_caller_scb,
		   cheri_gettag(scbp->scb_caller_scb),
		   cheri_getlen(scbp->scb_caller_scb));
		return (false);
	}

	colocation_copyin_scb(scbp->scb_caller_scb, scbp);

	return (true);
}

static bool
colocation_fetch_callee_scb(struct thread *td, struct switchercb *scbp)
{
	if (td->td_scb == NULL) {
		/*
		 * We've never called cosetup(2).
		 */
		return (false);
	}

	colocation_copyin_scb(td->td_scb, scbp);

	if (cheri_gettag(scbp->scb_callee_scb) == 0 ||
	    cheri_getlen(scbp->scb_callee_scb) == 0) {
		/*
		 * Not in cocall.
		 */
		return (false);
	}

	colocation_copyin_scb(scbp->scb_callee_scb, scbp);

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

	chan = (__cheri_fromcap const void *)curthread->td_scb;

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

	*peertdp = (__cheri_fromcap struct thread *)scb.scb_borrower_td;
}

void
colocation_thread_exit(struct thread *td)
{
	struct vmspace *vmspace;
	struct coname *con, *con_temp;
	void * __capability scb_cap;
	struct switchercb scb;
	bool have_scb;

	have_scb = colocation_fetch_scb(td, &scb);
	if (!have_scb)
		return;

	if (counregister_on_exit) {
		scb_cap = cheri_seal(td->td_scb, switcher_sealcap2);

		vmspace = td->td_proc->p_vmspace;

		vm_map_lock(&vmspace->vm_map);

		LIST_FOREACH_SAFE(con, &vmspace->vm_conames, c_next, con_temp) {
			if (con->c_value == scb_cap) {
				LIST_REMOVE(con, c_next);
				free(con, M_TEMP);
			}
		}

		vm_map_unlock(&vmspace->vm_map);
	}

	/*
	 * Wake up any thread waiting on cocall_slow(2).
	 */
	wakeupself();

	COLOCATION_DEBUG("terminating thread %p, scb %lp",
	    td, td->td_scb);

	/*
	 * Set scb_caller_scb to a special "null" capability, so that cocall(2)
	 * can see the callee thread is dead.
	 */
	scb.scb_caller_scb = cheri_capability_build_user_data(0, 0, 0, ENOLINK);
	scb.scb_td = NULL;
	scb.scb_borrower_td = NULL;

	colocation_store_scb(td, &scb);
	td->td_scb = NULL;
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
	struct trapframe peertrapframe;
#ifdef __aarch64__
	uintcap_t peertpidr;
#endif
	bool have_scb;

	have_scb = colocation_fetch_scb(td, &scb);
	if (!have_scb)
		return;

	peertd = (__cheri_fromcap struct thread *)scb.scb_borrower_td;
	if (peertd == NULL) {
		/*
		 * Nothing borrowed yet.
		 */
		return;
	}

#if   defined(__riscv)
	KASSERT(td->td_frame->tf_t[0] != SYS_copark,
	    ("%s: unborrowing for copark(); peer td_sa.code %ld; td %p, pid %d (%s); peer td %p, peer pid %d (%s)\n",
	    __func__, (long)peertd->td_frame->tf_t[0],
	    td, td->td_proc->p_pid, td->td_proc->p_comm,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm));
#elif defined(__aarch64__)
	KASSERT(td->td_frame->tf_x[8] != SYS_copark,
	    ("%s: unborrowing for copark(); peer td_sa.code %ld; td %p, pid %d (%s); peer td %p, peer pid %d (%s)\n",
	    __func__, (long)peertd->td_frame->tf_x[8],
	    td, td->td_proc->p_pid, td->td_proc->p_comm,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm));
#else
#error "what architecture is this?"
#endif

	KASSERT(td == (__cheri_fromcap struct thread *)scb.scb_td,
	    ("%s: td %p != scb_td %p\n", __func__, td, (__cheri_fromcap struct thread *)scb.scb_td));
	KASSERT(peertd != td,
	    ("%s: peertd %p == td %p\n", __func__, peertd, td));

	COLOCATION_DEBUG("replacing current td %p, pid %d (%s), switchercb %lp, "
	    "with td %p, pid %d (%s), switchercb %lp",
	    td, td->td_proc->p_pid, td->td_proc->p_comm, td->td_scb,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm, peertd->td_scb);

#ifdef DDB
	if (kdb_on_unborrow)
		kdb_enter(KDB_WHY_CHERI, "unborrow");
#endif


#ifdef __aarch64__
	/*
	 * On aarch64, the TLS pointer is in TPC, not in td_frame.
	 */
	peertpidr = peertd->td_pcb->pcb_tpidr_el0;
	peertd->td_pcb->pcb_tpidr_el0 = td->td_pcb->pcb_tpidr_el0;
	td->td_pcb->pcb_tpidr_el0 = peertpidr;
#endif

	memcpy(&peertrapframe, peertd->td_frame, sizeof(struct trapframe));
	memcpy(peertd->td_frame, td->td_frame, sizeof(struct trapframe));
	memcpy(td->td_frame, &peertrapframe, sizeof(struct trapframe));

	/*
	 * Wake up the other thread, which should return with ERESTART,
	 * refetch its args from the updated trapframe, and then execute
	 * whatever syscall we've just entered.
	 */
	wakeup(&peertd->td_scb);

	/*
	 * Continue as usual, but calling copark(2) instead of whatever
	 * syscall it was.  The cpu_fetch_syscall_args() will fetch updated
	 * arguments from the stack frame.
	 */
#if   defined(__riscv)
	KASSERT(td->td_frame->tf_t[0] == SYS_copark,
	    ("%s: td_sa.code %ld != SYS_copark %d; peer td_sa.code %ld; td %p, pid %d (%s); peer td %p, peer pid %d (%s)\n",
	    __func__, (long)td->td_frame->tf_t[0], SYS_copark, (long)peertd->td_frame->tf_t[0],
	    td, td->td_proc->p_pid, td->td_proc->p_comm,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm));
#elif defined(__aarch64__)
	KASSERT(td->td_frame->tf_x[8] == SYS_copark,
	    ("%s: td_sa.code %ld != SYS_copark %d; peer td_sa.code %ld; td %p, pid %d (%s); peer td %p, peer pid %d (%s)\n",
	    __func__, (long)td->td_frame->tf_x[8], SYS_copark, (long)peertd->td_frame->tf_x[8],
	    td, td->td_proc->p_pid, td->td_proc->p_comm,
	    peertd, peertd->td_proc->p_pid, peertd->td_proc->p_comm));
#else
#error "what architecture is this?"
#endif

	scb.scb_borrower_td = NULL;
	colocation_store_scb(td, &scb);
}

bool
colocation_trap_in_switcher(struct thread *td, struct trapframe *trapframe,
    const char *msg)
{
	const struct sysentvec *sv;
	vm_offset_t addr;

	sv = td->td_proc->p_sysent;
	addr = TRAPF_PC(trapframe);

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


#ifdef __aarch64__
int
copyuser(const void * __restrict __capability src,
    void * __restrict __capability dst, size_t len)
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
		COLOCATION_DEBUG("copyin failed with error %d", error);
		goto out;
	}
	error = copyoutcap(tmpbuf, dst, len);
	if (error != 0) {
		COLOCATION_DEBUG("copyout failed with error %d", error);
		goto out;
	}
out:
	free(tmpbuf, M_TEMP);
	return (error);
}
#endif /* __aarch64__ */

/*
 * Setup the per-thread switcher control block.
 */
static int
setup_scb(struct thread *td)
{
	struct switchercb scb;
	vm_map_t map;
	vm_pointer_t addr;
	int rv;

	KASSERT(td->td_scb == NULL, ("%s: already initialized\n", __func__));

	map = &td->td_proc->p_vmspace->vm_map;

	addr = vm_map_min(map);
	rv = vm_map_find(map, NULL, 0, &addr, PAGE_SIZE, 0, VMFS_OPTIMAL_SPACE,
	    VM_PROT_RW_CAP, VM_PROT_RW_CAP, MAP_DISABLE_COREDUMP |
	    MAP_KERNEL_OWNER);
	if (rv != KERN_SUCCESS) {
		COLOCATION_DEBUG("vm_map_find() failed with rv %d", rv);
		return (ENOMEM);
	}

#ifdef __CHERI_PURE_CAPABILITY__
	td->td_scb = (void *)addr;
#else
	td->td_scb = cheri_capability_build_user_data(CHERI_CAP_USER_DATA_PERMS,
	    addr, PAGE_SIZE, 0);
#endif

	//printf("%s: scb at %p, td %p\n", __func__, (void *)addr, td);
	memset(&scb, 0, sizeof(scb));
	scb.scb_unsealcap = switcher_sealcap2;
	scb.scb_td = (__cheri_tocap void * __capability)td;
	scb.scb_borrower_td = NULL;
	scb.scb_caller_scb = cheri_capability_build_user_data(0, 0, 0, EAGAIN);
	colocation_store_scb(td, &scb);

	return (0);
}

int
sys__cosetup(struct thread *td, struct _cosetup_args *uap)
{

	return (kern_cosetup(td, uap->what, uap->code, uap->data));
}

static void * __capability
switcher_code_cap(struct thread *td, ptraddr_t base, size_t length)
{
	void * __capability codecap;

	/*
	 * This cannot use cheri_capability_build_user_code() as that
	 * function seals the resulting capability as a sentry.  This
	 * needs to seal the capability via the switcher_sealcap
	 * instead.
	 */
	codecap = cheri_capability_build_user_rwx(CHERI_CAP_USER_CODE_PERMS,
	    base, length, 0);
#ifndef __aarch64__
	/*
	 * XXX: Somehow makes every attempt at ldr/str in the switcher
	 *      fail with capability fault.
	 */
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI))
		codecap = cheri_capmode(codecap);
#endif
	return (codecap);
}

static void * __capability
rederive(const void * __capability from)
{
	void * __capability codecap;

	codecap = cheri_capability_build_inexact_user_rwx(CHERI_CAP_USER_CODE_PERMS,
	    cheri_getbase(from) + cheri_getoffset(from), cheri_getlength(from) - cheri_getoffset(from), 0);
	if (SV_PROC_FLAG(curthread->td_proc, SV_CHERI))
		codecap = cheri_capmode(codecap);

	//printf("%s: %#lp -> %#lp\n", __func__, from, codecap);
	return (codecap);
}

int
kern_cosetup(struct thread *td, int what,
    void * __capability * __capability codep,
    void * __capability * __capability datap)
{
	void * __capability codecap;
	void * __capability datacap;
	struct vmspace *vmspace;
	int error;

	KASSERT(switcher_sealcap != (void * __capability)-1,
             ("%s: uninitialized switcher_sealcap", __func__));
	KASSERT(switcher_sealcap2 != (void * __capability)-1,
             ("%s: uninitialized switcher_sealcap2", __func__));
	KASSERT(switcher_sealcap != switcher_sealcap2,
             ("%s: switcher_sealcap == switcher_sealcap2", __func__));

	if (td->td_scb == NULL) {
		error = setup_scb(td);
		if (error != 0)
			return (error);
	}

	vmspace = td->td_proc->p_vmspace;

	switch (what) {
	case COSETUP_COCALL:
		if (vmspace->vm_cocall_codecap != NULL) {
			codecap = vmspace->vm_cocall_codecap;
			codecap = cheri_capmode(codecap);
		} else {
			codecap = switcher_code_cap(td,
			    td->td_proc->p_sysent->sv_cocall_base,
			    td->td_proc->p_sysent->sv_cocall_len);
		}
		codecap = cheri_seal(codecap, switcher_sealcap);
		error = sucap(codep, (intcap_t)codecap);
		if (error != 0)
			return (error);

		datacap = cheri_seal(td->td_scb, switcher_sealcap);
		error = sucap(datap, (intcap_t)datacap);
		return (error);

	case COSETUP_COACCEPT:
		if (vmspace->vm_coaccept_codecap != NULL) {
			codecap = vmspace->vm_coaccept_codecap;
			codecap = cheri_capmode(codecap);
		} else {
			codecap = switcher_code_cap(td,
			    td->td_proc->p_sysent->sv_coaccept_base,
			    td->td_proc->p_sysent->sv_coaccept_len);
		}
		codecap = cheri_seal(codecap, switcher_sealcap);
		error = sucap(codep, (intcap_t)codecap);
		if (error != 0)
			return (error);

		datacap = cheri_seal(td->td_scb, switcher_sealcap);
		error = sucap(datap, (intcap_t)datacap);
		return (error);

	case COSETUP_TAKEOVER:
		error = priv_check(td, PRIV_KMEM_WRITE);
		if (error != 0) {
			COLOCATION_DEBUG("COSETUP_TAKEOVER failing with error %d", error);
			return (error);
		}

		if (vmspace->vm_cocall_codecap != NULL || vmspace->vm_coaccept_codecap != NULL)
			return (EBUSY);

		error = fuecap(codep, (intcap_t *)&codecap);
		if (error != 0) {
			COLOCATION_DEBUG("COSETUP_TAKEOVER: failed to fetch cocall cap from %#lp, error %d", codep, error);
			return (error);
		}
		error = fuecap(datap, (intcap_t *)&datacap);
		if (error != 0) {
			COLOCATION_DEBUG("COSETUP_TAKEOVER: failed to fetch coaccept cap from %#lp, error %d", datap, error);
			return (error);
		}

		vmspace->vm_cocall_codecap = rederive(codecap);
		vmspace->vm_coaccept_codecap = rederive(datacap);

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
	int error;

	vmspace = td->td_proc->p_vmspace;

	if (td->td_scb == NULL) {
		error = setup_scb(td);
		if (error != 0)
			return (error);
	}

	cap = cheri_seal(td->td_scb, switcher_sealcap2);

	if (capp != NULL) {
		error = sucap(capp, (intcap_t)cap);
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
	intcap_t cap;
	char name[PATH_MAX];
	int error;

	if (!allow_colookup)
		return (ENOSYS);

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

	cap = (intcap_t)con->c_value;
	vm_map_unlock_read(&vmspace->vm_map);
	error = sucap(capp, cap);
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
	error = copyout(&pid, pidp, sizeof(pid));

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
	error = msleep(&td->td_scb, &switcher_lock,
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
	struct switchercb * __capability targetscb;
	struct thread *calleetd __diagused;
	ssize_t received;
	int error;
	bool have_scb;

	if (outbuf == NULL && outlen != 0) {
		COLOCATION_DEBUG("outbuf == NULL, but outlen != 0, returning EINVAL");
		return (EINVAL);
	}
	if (inbuf == NULL && inlen != 0) {
		COLOCATION_DEBUG("inbuf == NULL, but inlen != 0, returning EINVAL");
		return (EINVAL);
	}

	have_scb = colocation_fetch_scb(curthread, &scb);
	if (!have_scb) {
		COLOCATION_DEBUG("no scb, returning EINVAL");
		return (EINVAL);
	}

	curproc->p_cocall_received = 0;

	/*
	 * Unseal the capability to the callee control block and load it.
	 *
	 * XXX: We could drop those three checks once we have a non-trapping unseal.
	 */
	if (cheri_gettag(target) == 0) {
		COLOCATION_DEBUG("untagged target %#lp; returning EINVAL", target);
		return (EINVAL);
	}
	if (cheri_getsealed(target) == 0) {
		COLOCATION_DEBUG("unsealed target %#lp; returning EINVAL", target);
		return (EINVAL);
	}
	if (cheri_gettype(target) == cheri_gettype(switcher_sealcap2)) {
		COLOCATION_DEBUG("target %#lp type %lu != %#lp type %lu; returning EINVAL",
		    target, cheri_gettype(target),
		    switcher_sealcap2, cheri_gettype(switcher_sealcap2));
		return (EINVAL);
	}

	targetscb = cheri_unseal(target, switcher_sealcap2);

	SWITCHER_LOCK();
	COLOCATION_DEBUG("starting with target %#lp", targetscb);
again:
	colocation_copyin_scb(targetscb, &calleescb);

	/*
	 * The protocol here is slightly different from the one used
	 * by the switcher; this is to signal an error when the user
	 * attempts to use kernel {cocall,coaccept}_slow() against
	 * switcher {cocall,coaccept}().  Instead of signalling the
	 * "available" status with NULL capability, instead we encode
	 * it as zero-length capability, with offset set to EPROTOTYPE.
	 */

	if (cheri_gettag(calleescb.scb_caller_scb) == 0) {
		COLOCATION_DEBUG("callee scb %#lp is waiting on switcher cocall", targetscb);
		SWITCHER_UNLOCK();
		return (EPROTOTYPE);
	}

	if (cheri_getlen(calleescb.scb_caller_scb) != 0) {
		/*
		 * Non-zero length means there's already a cocall in progress.
		 */
		COLOCATION_DEBUG("callee is busy, waiting on %lp", targetscb);
		error = msleep((__cheri_fromcap const void *)targetscb,
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

	colocation_store_caller_scb(targetscb, curthread->td_scb);

	scb.scb_callee_scb = targetscb;
	scb.scb_outbuf = outbuf;
	scb.scb_outlen = outlen;
	scb.scb_inbuf = inbuf;
	scb.scb_inlen = inlen;
	/*
	 * We don't need atomics here; nobody else could have modified
	 * our (caller's) SCB.
	 */
	colocation_store_scb(curthread, &scb);

	calleetd = (__cheri_fromcap struct thread *)calleescb.scb_td;
	KASSERT(calleetd != NULL, ("%s: NULL calleetd?\n", __func__));

	// XXX: What happens when the callee thread dies while we are here?
	//      We need to hold it somehow.

	/*
	 * Wake up the callee and wait for them to copy the buffer,
	 * return from coaccept_slow(2), call coaccept_slow(2) again,
	 * and copy the buffer back.
	 */
	wakeupcap(targetscb, "callee");
	COLOCATION_DEBUG("waiting on scb %lp", targetscb);
	error = msleep((__cheri_fromcap const void *)targetscb,
	    &switcher_lock, PCATCH, "cocall", 0);
	// XXX: Are we sure we are done once we wake up?
	if (error != 0 && error != ERESTART) {
		COLOCATION_DEBUG("msleep failed with error %d", error);
	}

	colocation_store_caller_scb(targetscb,
	    cheri_capability_build_user_data(0, 0, 0, EPROTOTYPE));

	/*
	 * Wake up other callers that might be waiting in kern_cocall_slow().
	 */
	wakeupcap(targetscb, "callers sleeping on callee");
	SWITCHER_UNLOCK();

	/*
	 * Return the error stored by the callee.
	 */
	received = curproc->p_cocall_received;
	if (received >= 0) {
		curthread->td_retval[0] = received;
		return (0);
	}

	return (-received);
}

int
sys_cocall_slow(struct thread *td, struct cocall_slow_args *uap)
{

	return (kern_cocall_slow(uap->target,
	    uap->outbuf, uap->outlen, uap->inbuf, uap->inlen));
}

int
kern_coaccept_slow(void * __capability * __capability cookiep,
    const void * __capability outbuf, size_t outlen,
    void * __capability inbuf, size_t inlen)
{
	struct switchercb scb, callerscb;
	void * __capability cookie;
	size_t copied;
	int error;
	bool have_scb, is_callee;

	if (outbuf == NULL && outlen != 0) {
		COLOCATION_DEBUG("outbuf == NULL, but outlen != 0, returning EINVAL");
		return (EINVAL);
	}
	if (inbuf == NULL && inlen != 0) {
		COLOCATION_DEBUG("inbuf == NULL, but inlen != 0, returning EINVAL");
		return (EINVAL);
	}

	SWITCHER_LOCK();
	have_scb = colocation_fetch_scb(curthread, &scb);
	if (!have_scb) {
		SWITCHER_UNLOCK();
		COLOCATION_DEBUG("no scb, returning EINVAL");
		return (EINVAL);
	}

	COLOCATION_DEBUG("read scb_caller_scb %#lp from scb %#lp",
	    scb.scb_caller_scb, curthread->td_scb);
	if (cheri_getlen(scb.scb_caller_scb) == 0) {
		/*
		 * Offset-encoded EPROTOTYPE means there's a coaccept_slow(2)
		 * waiting.
		 *
		 * No atomics needed here; couldn't have raced with cocall(2),
		 * as it would bounce due to scb_caller_scb not being NULL;
		 * couldn't have raced with coaccept(2), because a thread cannot
		 * call coaccept_slow(2) and coaccept(2) at the same time.
		 */
		colocation_store_caller_scb(curthread->td_scb,
		    cheri_capability_build_user_data(0, 0, 0, EPROTOTYPE));
	} else {
		/*
		 * There's a caller waiting for us, get them their data
		 * and wake them up.
		 */
		is_callee = colocation_fetch_caller_scb(curthread, &callerscb);
		KASSERT(is_callee, ("%s: no caller?", __func__));

		/*
		 * Move data from callee to caller.
		 *
		 * XXX MOVE THIS SOMEWHERE FFS
		 */
		copied = MIN(outlen, callerscb.scb_inlen);
		error = copyuser(outbuf, callerscb.scb_inbuf, copied);
		if (error != 0) {
			callerscb.scb_td->td_proc->p_cocall_received = -error;
			SWITCHER_UNLOCK();
			COLOCATION_DEBUG("copyuser error %d, waking up %lp",
			    error, callerscb.scb_td->td_scb);
			wakeupself();
			return (error);
		}
		callerscb.scb_td->td_proc->p_cocall_received = copied;

		wakeupself();
	}

again:
	/*
	 * Wait for new caller.
	 */
	COLOCATION_DEBUG("waiting on %lp", curthread->td_scb);
	error = msleep((__cheri_fromcap const void *)curthread->td_scb,
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
	copied = MIN(inlen, callerscb.scb_outlen); // XXX
	error = copyuser(callerscb.scb_outbuf, inbuf, copied);
	if (error != 0) {
		COLOCATION_DEBUG("copyuser error %d", error);
		wakeupself();
		return (error);
	}

	/*
	 * Fill in the caller cookie.
	 */
	if (cookiep != NULL) {
		cookie = cheri_cleartag(scb.scb_caller_scb);
		error = sucap(cookiep, (intcap_t)cookie);
		if (error != 0) {
			COLOCATION_DEBUG("sucap error %d", error);
			wakeupself();
			return (error);
		}
	}

	curthread->td_retval[0] = copied;
	return (0);
}

int
sys_coaccept_slow(struct thread *td, struct coaccept_slow_args *uap)
{

	return (kern_coaccept_slow(uap->cookiep,
	    uap->outbuf, uap->outlen, uap->inbuf, uap->inlen));
}

/*
 * XXX: Twose two seem a bit... too simple.  Proceed with caution.
 *
 * XXX: Perhaps we should make sure that both sides are running
 *      in the same address space.  But if they're not, then
 *      there is no way to pass the capability in the first place.
 */
int
sys_capfromfd(struct thread *td, struct capfromfd_args *uap)
{
	void * __capability fcap;
	struct file *fp;
	cap_rights_t rights;
	int error;

	KASSERT(capfd_sealcap != (void * __capability)-1,
             ("%s: uninitialized capfd_sealcap", __func__));
	KASSERT(capfd_sealcap != switcher_sealcap,
             ("%s: capfd_sealcap == switcher_sealcap", __func__));
	KASSERT(capfd_sealcap != switcher_sealcap2,
             ("%s: capfd_sealcap == switcher_sealcap2", __func__));

	error = fget(curthread, uap->fd, cap_rights_init_one(&rights, CAP_SOCK_CLIENT), &fp);
	if (error != 0) {
		COLOCATION_DEBUG("fget error %d", error);
		return (error);
	}
	if (!(fp->f_ops->fo_flags & DFLAG_PASSABLE)) {
		COLOCATION_DEBUG("DFLAG_PASSABLE set; returning EOPNOTSUPP");
		fdrop(fp, curthread);
		return (EOPNOTSUPP);
	}

	fcap = (void * __capability)fp;
	fcap = cheri_seal(fcap, capfd_sealcap);
	error = sucap(uap->capp, (intcap_t)fcap);
	if (error != 0)
		COLOCATION_DEBUG("sucap error %d", error);

	/*
	 * XXX: We never free that fp.  Plan is to use garbage collection
	 *      to reclaim the sealed cap.  In the meantime we could call
	 *      fdrop(9) when the calling process exits, but we would still
	 *      need a mechanism to prevent address reuse for the sealed cap.
	 */

	return (error);
}

int
sys_captofd(struct thread *td, struct captofd_args *uap)
{
	void * __capability fcap;
	struct file *fp;
	int error, fd;

	fcap = uap->cap;

	/*
	 * XXX: We could drop those three checks once we have a non-trapping unseal.
	 */
	if (cheri_gettag(fcap) == 0) {
		COLOCATION_DEBUG("untagged fcap %#lp; returning EINVAL", fcap);
		return (EINVAL);
	}
	if (cheri_getsealed(fcap) == 0) {
		COLOCATION_DEBUG("unsealed fcap %#lp; returning EINVAL", fcap);
		return (EINVAL);
	}
	if (cheri_gettype(fcap) == cheri_gettype(capfd_sealcap)) {
		COLOCATION_DEBUG("fcap %#lp type %lu != %#lp type %lu; returning EINVAL",
		    fcap, cheri_gettype(fcap),
		    capfd_sealcap, cheri_gettype(capfd_sealcap));
		return (EINVAL);
	}

	fcap = cheri_unseal(fcap, capfd_sealcap);
	if (fcap == NULL) {
		/*
		 * XXX: This code path is completely untested
		 *      due to cheri_unseal() trapping.
		 */
		COLOCATION_DEBUG("cheri_unseal failed");
		return (EINVAL);
	}

	fp = (__cheri_fromcap struct file *)fcap;
	error = finstall(td, fp, &fd, 0, NULL);
	if (error != 0) {
		COLOCATION_DEBUG("finstall error %d", error);
		return (error);
	}

	error = copyout(&fd, uap->fdp, sizeof(fd));
	return (0);
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
	db_print_cap(td, "    scb_td:            ", scb->scb_td);
	db_print_cap(td, "    scb_borrower_td:   ", scb->scb_borrower_td);
	db_print_cap(td, "    scb_unsealcap:     ", scb->scb_unsealcap);
	db_print_cap(td, "    scb_csp:           ", scb->scb_csp);
	db_print_cap(td, "    scb_cra:           ", scb->scb_cra);
	db_print_cap(td, "    scb_cookiep (ca2): ", scb->scb_cookiep);
	db_print_cap(td, "    scb_outbuf (ca3):  ", scb->scb_outbuf);
	db_printf(       "    scb_outlen (a4):   %zd\n", scb->scb_outlen);
	db_print_cap(td, "    scb_inbuf (ca5):   ", scb->scb_inbuf);
	db_printf(       "    scb_inlen (a6):    %zd\n", scb->scb_inlen);
	db_print_cap(td, "    scb_cookiep:       ", scb->scb_cookiep);
#ifdef __aarch64__
	db_print_cap(td, "    scb_c19:           ", scb->scb_c19);
	db_print_cap(td, "    scb_c20:           ", scb->scb_c20);
	db_print_cap(td, "    scb_c21:           ", scb->scb_c21);
	db_print_cap(td, "    scb_c22:           ", scb->scb_c22);
	db_print_cap(td, "    scb_c23:           ", scb->scb_c23);
	db_print_cap(td, "    scb_c24:           ", scb->scb_c24);
	db_print_cap(td, "    scb_c25:           ", scb->scb_c25);
	db_print_cap(td, "    scb_c26:           ", scb->scb_c26);
	db_print_cap(td, "    scb_c27:           ", scb->scb_c27);
	db_print_cap(td, "    scb_c28:           ", scb->scb_c28);
	db_print_cap(td, "    scb_tls:           ", scb->scb_tls);
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

#if   defined(__riscv)
	addr = __builtin_cheri_address_get(td->td_frame->tf_sp);
//	db_printf("%s: td: %p; td_frame %p; tf_sp: %#lp; csp addr: %lx\n",
//	    __func__, td, td->td_frame,
//	    (void * __capability)td->td_frame->tf_sp, (long)addr);
#elif defined(__aarch64__)
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
		error = copyincap(___USER_CFROMPTR(addr, userspace_root_cap),
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
		db_printf(" switcher control block %#lp for curthread %p, pid %d (%s), stack owned by %d:\n",
		    td->td_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
		db_print_scb_td(td);

		borrowertd = (__cheri_fromcap struct thread *)scb.scb_borrower_td;
		shown_borrowertd = false;

		have_scb = colocation_fetch_caller_scb(td, &scb);
		if (have_scb) {
			if (borrowertd != (__cheri_fromcap struct thread *)scb.scb_td) {
				td = (__cheri_fromcap struct thread *)scb.scb_td;
				p = td->td_proc;
				db_printf(" caller's SCB %#lp owned by thread %p, pid %d (%s), stack owned by %d:\n",
				    td->td_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
			} else {
				td = borrowertd;
				p = td->td_proc;
				db_printf(" caller's SCB %#lp for borrowing thread %p, pid %d (%s), stack owned by %d:\n",
				    td->td_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
				shown_borrowertd = true;
			}
			db_print_scb(td, &scb);
		}

		td = curthread;
		have_scb = colocation_fetch_callee_scb(td, &scb);
		if (have_scb) {
			if (borrowertd != (__cheri_fromcap struct thread *)scb.scb_td) {
				td = (__cheri_fromcap struct thread *)scb.scb_td;
				p = td->td_proc;
				db_printf(" callee's SCB %#lp owned by thread %p, pid %d (%s), stack owned by %d:\n",
				    td->td_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
			} else {
				td = borrowertd;
				p = td->td_proc;
				db_printf(" callee's SCB %#lp for borrowing thread %p, pid %d (%s), stack owned by %d:\n",
				    td->td_scb, td, p->p_pid, p->p_comm, db_get_stack_pid(td));
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
#else /* !__has_feature(capabilities) */
int
sys__cosetup(struct thread *td, struct _cosetup_args *uap)
{
	return (ENOSYS);
}

int
sys_coregister(struct thread *td, struct coregister_args *uap)
{
	return (ENOSYS);
}

int
sys_colookup(struct thread *td, struct colookup_args *uap)
{
	return (ENOSYS);
}

int
sys_copark(struct thread *td, struct copark_args *uap)
{
	return (ENOSYS);
}

int
sys_cogetpid(struct thread *td, struct cogetpid_args *uap)
{
	return (ENOSYS);
}

int
sys_cocall_slow(struct thread *td, struct cocall_slow_args *uap)
{
	return (ENOSYS);
}

int
sys_coaccept_slow(struct thread *td, struct coaccept_slow_args *uap)
{
	return (ENOSYS);
}

int
sys_capfromfd(struct thread *td, struct capfromfd_args *uap)
{
	return (ENOSYS);
}

int
sys_captofd(struct thread *td, struct captofd_args *uap)
{
	return (ENOSYS);
}

#endif /* __has_feature(capabilities) */
