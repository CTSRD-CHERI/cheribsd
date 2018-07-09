/*-
 * Copyright (c) 2015-2016 Nuxi, https://nuxi.nl/
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

#include <sys/param.h>
#include <sys/imgact.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/sysent.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/frame.h>
#include <machine/pcb.h>
#include <machine/vmparam.h>

#include <compat/cloudabi/cloudabi_util.h>

#include <compat/cloudabi32/cloudabi32_syscall.h>
#include <compat/cloudabi32/cloudabi32_util.h>

extern const char *cloudabi32_syscallnames[];
extern struct sysent cloudabi32_sysent[];

static int
cloudabi32_fixup_tcb(register_t **stack_base, struct image_params *imgp)
{
	int error;
	uint32_t args[2];

	/* Place auxiliary vector and TCB on the stack. */
	error = cloudabi32_fixup(stack_base, imgp);
	if (error != 0)
		return (error);

	/*
	 * On i386, the TCB is referred to by %gs:0. Reuse the empty
	 * space normally used by the return address (args[0]) to store
	 * a single element array, containing a pointer to the TCB. %gs
	 * base will point to this.
	 *
	 * Also let the first argument of the entry point (args[1])
	 * refer to the auxiliary vector, which is stored right after
	 * the TCB.
	 */
	args[0] = (uintptr_t)*stack_base;
	args[1] = (uintptr_t)*stack_base +
	    roundup(sizeof(cloudabi32_tcb_t), sizeof(register_t));
	*stack_base -= howmany(sizeof(args), sizeof(register_t));
	return (copyout(args, *stack_base, sizeof(args)));
}

static void
cloudabi32_proc_setregs(struct thread *td, struct image_params *imgp,
    unsigned long stack)
{

	exec_setregs(td, imgp, stack);
	(void)cpu_set_user_tls(td, TO_PTR(stack));
}

static int
cloudabi32_fetch_syscall_args(struct thread *td)
{
	struct trapframe *frame;
	struct syscall_args *sa;
	int error;

	frame = td->td_frame;
	sa = &td->td_sa;

	/* Obtain system call number. */
	sa->code = frame->tf_eax;
	if (sa->code >= CLOUDABI32_SYS_MAXSYSCALL)
		return (ENOSYS);
	sa->callp = &cloudabi32_sysent[sa->code];
	sa->narg = sa->callp->sy_narg;

	/* Fetch system call arguments from the stack. */
	error = copyin((void *)(frame->tf_esp + 4), sa->args,
	    sa->narg * sizeof(sa->args[0]));
	if (error != 0)
		return (error);

	/* Default system call return values. */
	td->td_retval[0] = 0;
	td->td_retval[1] = frame->tf_edx;
	return (0);
}

static void
cloudabi32_set_syscall_retval(struct thread *td, int error)
{
	struct trapframe *frame = td->td_frame;

	switch (error) {
	case 0:
		/* System call succeeded. */
		frame->tf_eax = td->td_retval[0];
		frame->tf_edx = td->td_retval[1];
		frame->tf_eflags &= ~PSL_C;
		break;
	case ERESTART:
		/* Restart system call. */
		frame->tf_eip -= frame->tf_err;
		break;
	case EJUSTRETURN:
		break;
	default:
		/* System call returned an error. */
		frame->tf_eax = cloudabi_convert_errno(error);
		frame->tf_eflags |= PSL_C;
		break;
	}
}

static void
cloudabi32_schedtail(struct thread *td)
{
	struct trapframe *frame = td->td_frame;

	/* Initial register values for processes returning from fork. */
	frame->tf_eax = CLOUDABI_PROCESS_CHILD;
	frame->tf_edx = td->td_tid;
}

int
cloudabi32_thread_setregs(struct thread *td,
    const cloudabi32_threadattr_t *attr, uint32_t tcb)
{
	stack_t stack;
	uint32_t args[3];
	void *frameptr;
	int error;

	/* Perform standard register initialization. */
	stack.ss_sp = TO_PTR(attr->stack);
	stack.ss_size = attr->stack_len - sizeof(args);
	cpu_set_upcall(td, TO_PTR(attr->entry_point), NULL, &stack);

	/*
	 * Copy the arguments for the thread entry point onto the stack
	 * (args[1] and args[2]). Similar to process startup, use the
	 * otherwise unused return address (args[0]) for TLS.
	 */
	args[0] = tcb;
	args[1] = td->td_tid;
	args[2] = attr->argument;
	frameptr = (void *)td->td_frame->tf_esp;
	error = copyout(args, frameptr, sizeof(args));
	if (error != 0)
		return (error);

	return (cpu_set_user_tls(td, frameptr));
}

static struct sysentvec cloudabi32_elf_sysvec = {
	.sv_size		= CLOUDABI32_SYS_MAXSYSCALL,
	.sv_table		= cloudabi32_sysent,
	.sv_fixup		= cloudabi32_fixup_tcb,
	.sv_name		= "CloudABI ELF32",
	.sv_coredump		= elf32_coredump,
	.sv_pagesize		= PAGE_SIZE,
	.sv_minuser		= VM_MIN_ADDRESS,
	.sv_maxuser		= VM_MAXUSER_ADDRESS,
	.sv_stackprot		= VM_PROT_READ | VM_PROT_WRITE,
	.sv_copyout_strings	= cloudabi32_copyout_strings,
	.sv_setregs		= cloudabi32_proc_setregs,
	.sv_flags		= SV_ABI_CLOUDABI | SV_CAPSICUM | SV_IA32 | SV_ILP32,
	.sv_set_syscall_retval	= cloudabi32_set_syscall_retval,
	.sv_fetch_syscall_args	= cloudabi32_fetch_syscall_args,
	.sv_syscallnames	= cloudabi32_syscallnames,
	.sv_schedtail		= cloudabi32_schedtail,
};

INIT_SYSENTVEC(elf_sysvec, &cloudabi32_elf_sysvec);

Elf32_Brandinfo cloudabi32_brand = {
	.brand		= ELFOSABI_CLOUDABI,
	.machine	= EM_386,
	.sysvec		= &cloudabi32_elf_sysvec,
	.flags		= BI_BRAND_ONLY_STATIC,
};
