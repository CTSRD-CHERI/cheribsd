/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * 
 * Copyright (c) 2020 Alfredo Mazzinghi
 * 
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <stdio.h>

#include <libprocstat.h>
#include <libxo/xo.h>

static xo_handle_t *xop = NULL;

static void
usage(void)
{
	warnx("usage: vmmap_dump (entry|exit) syscall_number command");
	exit (1);
}

static const char *
to_bool(int value)
{
	return ((value) ? "true" : "false");
}

static const char *
to_flag(const char *flag, int value)
{
	return ((value) ? flag : "-");
}

static void
dump_vm(pid_t pid)
{
	struct procstat *ps;
	struct kinfo_proc *kp;
	struct kinfo_vmentry *vmentry, *curr;
	int count, i;
	const char *str;

	ps = procstat_open_sysctl();
	if (ps == NULL)
		err(EX_OSERR, "procstat open");
	kp = procstat_getprocs(ps, KERN_PROC_PID, pid, &count);
	if (kp == NULL || count != 1)
		err(EX_OSERR, "procstat getprocs");
	vmentry = procstat_getvmmap(ps, kp, &count);
	if (vmentry == NULL)
		err(EX_OSERR, "procstat vmmap");

	xo_emit_h(xop, "{T:/%18s %18s %18s %5s %8s %16s %s}\n",
	    "RESERVATION", "START", "END", "PROT", "FLAGS", "TYPE", "PATH");
	xo_open_list_h(xop, "vm");
	for (i = 0; i < count; i++) {
		curr = &vmentry[i];
		xo_open_instance_h(xop, "vm");
		xo_emit_h(xop, "{w:reservation/%#018jx}",
		    (uintmax_t)curr->kve_reservation);
		xo_emit_h(xop, "{w:start/%#018jx}",
		    (uintmax_t)curr->kve_start);
		xo_emit_h(xop, "{w:end/%#018jx}",
		    (uintmax_t)curr->kve_end);

		xo_open_container_h(xop, "prot");
		xo_emit_h(xop, "{en:read/%s}",
		    to_bool(curr->kve_protection & KVME_PROT_READ));
		xo_emit_h(xop, "{en:write/%s}",
		    to_bool(curr->kve_protection & KVME_PROT_WRITE));
		xo_emit_h(xop, "{en:exec/%s}",
		    to_bool(curr->kve_protection & KVME_PROT_EXEC));
		xo_emit_h(xop, "{en:load_tags/%s}",
		    to_bool(curr->kve_protection & KVME_PROT_LOADTAGS));
		xo_emit_h(xop, "{en:store_tags/%s}",
		    to_bool(curr->kve_protection & KVME_PROT_STORETAGS));
		xo_emit_h(xop, "{d:read/%s}", to_flag("r",
		    curr->kve_protection & KVME_PROT_READ));
		xo_emit_h(xop, "{d:write/%s}", to_flag("w",
		    curr->kve_protection & KVME_PROT_WRITE));
		xo_emit_h(xop, "{d:exec/%s}", to_flag("x",
		    curr->kve_protection & KVME_PROT_EXEC));
		xo_emit_h(xop, "{d:load_tags/%s}", to_flag("l",
		    curr->kve_protection & KVME_PROT_LOADTAGS));
		xo_emit_h(xop, "{dw:store_tags/%s}", to_flag("s",
		    curr->kve_protection & KVME_PROT_STORETAGS));
		xo_close_container_h(xop, "prot");

		xo_open_container_h(xop, "flags");
		xo_emit_h(xop, "{en:cow/%s}",
		    to_bool(curr->kve_flags & KVME_FLAG_COW));
		xo_emit_h(xop, "{en:guard/%s}",
		    to_bool(curr->kve_flags & KVME_FLAG_GUARD));
		xo_emit_h(xop, "{en:unmapped/%s}",
		    to_bool(curr->kve_flags & KVME_FLAG_UNMAPPED));
		xo_emit_h(xop, "{en:need_copy/%s}",
		    to_bool(curr->kve_flags & KVME_FLAG_NEEDS_COPY));
		xo_emit_h(xop, "{en:super_pages/%s}",
		    to_bool(curr->kve_flags & KVME_FLAG_SUPER));
		xo_emit_h(xop, "{en:grows_up/%s}",
		    to_bool(curr->kve_flags & KVME_FLAG_GROWS_UP));
		xo_emit_h(xop, "{en:grows_down/%s}",
		    to_bool(curr->kve_flags & KVME_FLAG_GROWS_DOWN));
		xo_emit_h(xop, "{en:wired/%s}",
		    to_bool(curr->kve_flags & KVME_FLAG_USER_WIRED));

		xo_emit_h(xop, "{d:cow/%s}",
		    to_flag("C", curr->kve_flags & KVME_FLAG_COW));
		xo_emit_h(xop, "{d:guard/%s}",
		    to_flag("G", curr->kve_flags & KVME_FLAG_GUARD));
		xo_emit_h(xop, "{d:unmapped/%s}",
		    to_flag("R", curr->kve_flags & KVME_FLAG_UNMAPPED));
		xo_emit_h(xop, "{d:need_copy/%s}",
		    to_flag("N", curr->kve_flags & KVME_FLAG_NEEDS_COPY));
		xo_emit_h(xop, "{d:super_pages/%s}",
		    to_flag("S", curr->kve_flags & KVME_FLAG_SUPER));
		xo_emit_h(xop, "{d:grows_up/%s}",
		    to_flag("U", curr->kve_flags & KVME_FLAG_GROWS_UP));
		xo_emit_h(xop, "{d:grows_down/%s}",
		    to_flag("D", curr->kve_flags & KVME_FLAG_GROWS_DOWN));
		xo_emit_h(xop, "{dw:wired/%s}",
		    to_flag("W", curr->kve_flags & KVME_FLAG_USER_WIRED));
		xo_close_container_h(xop, "flags");

		switch (curr->kve_type) {
		case KVME_TYPE_NONE:
			str = "none";
			break;
		case KVME_TYPE_DEFAULT:
			str = "default";
			break;
		case KVME_TYPE_VNODE:
			str = "vnode";
			break;
		case KVME_TYPE_SWAP:
			str = "swap";
			break;
		case KVME_TYPE_DEVICE:
			str = "device";
			break;
		case KVME_TYPE_PHYS:
			str = "physical";
			break;
		case KVME_TYPE_DEAD:
			str = "dead";
			break;
		case KVME_TYPE_SG:
			str = "scatter/gather";
			break;
		case KVME_TYPE_MGTDEVICE:
			str = "managed_device";
			break;
		case KVME_TYPE_UNKNOWN:
		default:
			str = "unknown";
			break;
		}
		xo_emit_h(xop, "{w:type/%16s}", str);
		xo_emit_h(xop, "{:kve_path/%-s/%s}\n", curr->kve_path);
		xo_close_instance_h(xop, "vm");
	}
	xo_close_list_h(xop, "vm");

	procstat_freevmmap(ps, vmentry);
	procstat_freeprocs(ps, kp);
	procstat_close(ps);
}

static void
run_command(char **argv, bool entry, u_int sysnum)
{
	int status;
	pid_t pid;
	int request = (entry) ? PT_TO_SCE : PT_TO_SCX;
	int flag = (entry) ? PL_FLAG_SCE : PL_FLAG_SCX;
	struct ptrace_lwpinfo lwpi;

	pid = fork();
	if (pid < 0)
		err(EX_OSERR, "fork");
	if (pid == 0) {
		/* Setup tracing for the child */
		if (ptrace(PT_TRACE_ME, 0, NULL, 0) == -1)
			errx(EX_OSERR, "ptrace trace-me");
		if (execvp(argv[0], argv) == -1)
			err(EX_OSERR, "execvp");
	}

	waitpid(pid, &status, 0);
	if (!WIFSTOPPED(status))
		errx(EX_OSERR, "traced process did not stop");

	if (ptrace(request, pid, (caddr_t)1, 0) == -1)
		errx(EX_OSERR, "ptrace syscall");
	
	do {
		waitpid(pid, &status, 0);
		if (WIFSTOPPED(status)) {
			if (ptrace(PT_LWPINFO, pid, (caddr_t)&lwpi,
			    sizeof(lwpi)) == -1)
				errx(EX_OSERR, "ptrace lwpinfo");
			if (lwpi.pl_flags & flag) {
				if (lwpi.pl_syscall_code == sysnum)
					dump_vm(pid);
			}
			if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) == -1)
				errx(EX_OSERR, "ptrace continue");
			
		}
	} while (!(WIFEXITED(status) || WIFSIGNALED(status)));
}

int
main(int argc, char **argv)
{
	char *file;
	FILE *logfile;
	bool sysentry = false;
	int sysnum;

	/* Adjust argc and argv as though we've used getopt. */
	argc--;
	argv++;

	if (argc == 0)
		usage();

	if (strcmp("-j", argv[0]) == 0) {
		argv++;
		argc--;
		if (argc == 0)
			usage();
		file = argv[0];
		argv++;
		argc--;
		if (argc == 0)
			usage();
		logfile = fopen(file, "w+");
		if (logfile == NULL)
			err(EX_OSERR, "can not open logfile");
		xop = xo_create_to_file(logfile, XO_STYLE_JSON,
		    XOF_CLOSE_FP);
	}

	if (strcmp("entry", argv[0]) == 0)
		sysentry = true;
	else if (strcmp("exit", argv[0]) == 0)
		sysentry = false;
	else
		usage();

	argv++;
	argc--;
	if (argc == 0)
		usage();
	sysnum = atoi(argv[0]);

	argv++;
	argc--;
	if (argc == 0)
		usage();
	xo_open_container_h(xop, "vmmap_dump");
	run_command(argv, sysentry, sysnum);
	xo_close_container_h(xop, "vmmap_dump");
	xo_finish_h(xop);
}
