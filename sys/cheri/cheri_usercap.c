/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
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
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/systm.h>

#ifdef INVARIANTS
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#endif

#include <cheri/cheric.h>

/* Set to -1 to prevent it from being zeroed with the rest of BSS */
void * __capability userspace_root_cap = (void * __capability)(intcap_t)-1;

static u_int cheri_ptrace_caps;
SYSCTL_UINT(_security_cheri, OID_AUTO, ptrace_caps, CTLFLAG_RWTUN,
    &cheri_ptrace_caps, 0,
    "Control derivation of caps for ptrace: 0 = registers only; 1 = any valid userspace mapping; 2 = any userspace cap");

static u_long cheri_forged_ptrace_caps;
SYSCTL_ULONG(_security_cheri_stats, OID_AUTO, forged_ptrace_caps, CTLFLAG_RD,
    &cheri_forged_ptrace_caps, 0,
    "Number of forged capabilities injected via ptrace");

static u_long cheri_untagged_ptrace_caps;
SYSCTL_ULONG(_security_cheri_stats, OID_AUTO, untagged_ptrace_caps, CTLFLAG_RD,
    &cheri_untagged_ptrace_caps, 0,
    "Number of capabilities injected via ptrace that failed to tag");

/*
 * Build a new userspace capability derived from userspace_root_cap.
 * The resulting capability may include both read and execute permissions,
 * but not write, and will be a sentry capability. For architectures that use
 * flags, the flags for the resulting capability will be set based on what is
 * expected by userspace for the specified thread.
 */
void * __capability
_cheri_capability_build_user_code(struct thread *td, uint32_t perms,
    ptraddr_t basep, size_t length, off_t off, const char* func, int line)
{
	void * __capability tmpcap;

	KASSERT((perms & ~CHERI_CAP_USER_CODE_PERMS) == 0,
	    ("%s:%d: perms %x has permission not in CHERI_CAP_USER_CODE_PERMS %x",
	    func, line, perms, CHERI_CAP_USER_CODE_PERMS));

	tmpcap = _cheri_capability_build_user_rwx(
	    perms & CHERI_CAP_USER_CODE_PERMS, basep, length, off, func, line,
	    true);

	if (SV_PROC_FLAG(td->td_proc, SV_CHERI))
		tmpcap = cheri_capmode(tmpcap);

	return (cheri_sealentry(tmpcap));
}

/*
 * Build a new userspace capability derived from userspace_root_cap.
 * The resulting capability may include read and write permissions, but
 * not execute.
 */
void * __capability
_cheri_capability_build_user_data(uint32_t perms, ptraddr_t basep,
    size_t length, off_t off, const char* func, int line, bool exact)
{

	KASSERT((perms & ~CHERI_CAP_USER_DATA_PERMS) == 0,
	    ("%s:%d: perms %x has permission not in CHERI_CAP_USER_DATA_PERMS %x",
	    func, line, perms, CHERI_CAP_USER_DATA_PERMS));

	return (_cheri_capability_build_user_rwx(
	    perms & CHERI_CAP_USER_DATA_PERMS, basep, length, off, func, line,
	    exact));
}

/*
 * Build a new userspace capability derived from userspace_root_cap.
 * The resulting capability may include read, write, and execute permissions.
 *
 * This function violates W^X and its use is discouraged and the reason for
 * use should be documented in a comment when it is used.
 */
void * __capability
_cheri_capability_build_user_rwx(uint32_t perms, ptraddr_t basep, size_t length,
    off_t off, const char* func __unused, int line __unused, bool exact)
{
	void * __capability tmpcap;
#ifdef INVARIANTS
	vm_map_entry_t entry;
	vm_map_t map;
	vm_offset_t reservation;

	/*
	 * NB: Check skipped for unbounded PCC processes if attempting to
	 * derive a code capability for the whole user address space, since
	 * that is legitimately done.
	 */
	if (SV_CURPROC_FLAG(SV_CHERI) &&
	    !(SV_CURPROC_FLAG(SV_UNBOUND_PCC) &&
	      (perms & CHERI_CAP_USER_CODE_PERMS) == perms &&
	      basep == CHERI_CAP_USER_CODE_BASE &&
	      length == CHERI_CAP_USER_CODE_LENGTH)) {
		map = &curproc->p_vmspace->vm_map;
		vm_map_lock_read(map);
		KASSERT(vm_map_lookup_entry(map, basep, &entry),
		    ("%s:%d: vm_map does not contain basep 0x%zx "
		    "(length 0x%zu, offset 0x%ju)", func, line,
		    (size_t)basep, length, (uintmax_t)off));
		reservation = entry->reservation;
		for( ; basep + length > entry->end;
		    entry = vm_map_entry_succ(entry)) {
			/*
			 * Check that the created capability is within a
			 * single reservation.  This ensures we don't
			 * make capabilities that might alias with a
			 * later mapping.
			 */
			KASSERT((map->flags & MAP_RESERVATIONS) == 0 ||
			    entry->reservation == reservation,
			    ("Can't create a capability that spans reservations"));

			/*
			 * XXX: Disallow quarantined or abandoned pages?
			 *
			 * XXX: Require page maxprot to be a superset of
			 * perms?
			 */
		}
		vm_map_unlock_read(map);
	}
#endif

	tmpcap = _cheri_capability_build_user_rwx_unchecked(perms, basep,
	    length, off, func, line, exact);

	KASSERT(!exact || cheri_getlen(tmpcap) == length,
	    ("%s:%d: Constructed capability has wrong length 0x%zx != 0x%zx: "
	     "%#lp", func, line, cheri_getlen(tmpcap), length, tmpcap));

	return (tmpcap);
}

void * __capability
_cheri_capability_build_user_rwx_unchecked(uint32_t perms, ptraddr_t basep,
    size_t length, off_t off, const char* func __unused, int line __unused,
    bool exact)
{
	return (cheri_setoffset(cheri_andperm(cheri_setbounds(
	    cheri_setoffset(userspace_root_cap, basep), length), perms), off));
}

/*
 * Try to store a tagged capability in *out, derived from an untagged
 * "bag of bits" in in.  If a tagged capability cannot be derived,
 * return false and leave *out unchanged.
 */
bool
ptrace_derive_cap(struct proc *p, uintcap_t in, uintcap_t *out)
{
	struct thread *td;
	void * __capability cap;
	void * __capability sealcap;

	/*
	 * Try to derive from existing user registers in this
	 * process.
	 */
	FOREACH_THREAD_IN_PROC(p, td) {
		if (ptrace_derive_capreg_td(td, in, out))
			return (true);
	}

	if (cheri_ptrace_caps >= 1) {
		/* Try to derive from valid memory mappings. */
		if (vm_derive_capreg(p, in, out))
			return (true);
	}

	if (cheri_ptrace_caps >= 2) {
		/* If forging is allowed, derive from the userspace root. */
		cap = cheri_buildcap(userspace_root_cap, in);
		sealcap = cheri_copytype(userspace_root_sealcap, in);
		cap = cheri_condseal(cap, sealcap);
		if (cheri_gettag(cap)) {
			atomic_add_long(&cheri_forged_ptrace_caps, 1);
			*out = (uintcap_t)cap;
			return (true);
		}
	}

	atomic_add_long(&cheri_untagged_ptrace_caps, 1);
	return (false);
}
