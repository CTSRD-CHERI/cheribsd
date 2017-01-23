/*-
 * Copyright (c) 2016 Alfredo Mazzinghi
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/dirent.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <libprocstat.h>

#include <cheri/cheri.h>

#include <machine/sysarch.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <stdio.h>

static void
usage(void)
{
	warnx("usage: vmmap-dump <binary>");
	exit (1);
}

/*
 * Dump memory map of the process to csv file
 */
static void
extract_vmap(pid_t pid)
{
	/* struct ptrace_vm_entry pve; */
	char file_name[32];
	char path[1024];
	int count, i;
	FILE *csv;
	struct procstat *ps;
	struct kinfo_proc *kip;
	struct kinfo_vmentry *kve;
	
	sprintf(file_name, "vm_map_%06u.csv", pid);
	
	printf("Pid %u - extracting vm map to %s.\n", pid, file_name);
	csv = fopen(file_name, "w");
	if (csv == NULL)
		err(EX_CANTCREAT, "%s", file_name);
	fprintf(csv, "# PID, START, END, PRT, RES, PRES, "\
		"REF, SHADOW, FLAGS, TYPE, PATH\n");

	ps = procstat_open_sysctl();
	if (ps == NULL)
		err(EX_OSERR, "procstat_open_sysctl");

	kip = procstat_getprocs(ps, KERN_PROC_PID, pid, &count);
	if (kip == NULL)
		err(EX_OSERR, "procstat_getprocs");
	if (count != 1)
		err(EX_OSERR, "procstat_getprocs > 1 process with pid %u", pid);

	kve = procstat_getvmmap(ps, kip, &count);
	if (kve == NULL)
		err(EX_OSERR, "procstat_getvmmap");

	for (i = 0; i < count; i++) {
		fprintf(csv, "%lu, %lu, %lu, ",
			kve[i].kve_start,
			kve[i].kve_end,
			kve[i].kve_offset);
		if (kve[i].kve_protection & KVME_PROT_READ)
			fputc('r', csv);
		if (kve[i].kve_protection & KVME_PROT_WRITE)
			fputc('w', csv);
		if (kve[i].kve_protection & KVME_PROT_EXEC)
			fputc('x', csv);
		fputs(", ", csv);
		fprintf(csv, "%u, %u, %u, %u, ",
			kve[i].kve_resident,
			kve[i].kve_private_resident,
			kve[i].kve_ref_count,
			kve[i].kve_shadow_count);
		if (kve[i].kve_flags & KVME_FLAG_COW)
			fputc('C', csv);
		if (kve[i].kve_flags & KVME_FLAG_NEEDS_COPY)
			fputc('N', csv);
		if (kve[i].kve_flags & KVME_FLAG_SUPER)
			fputc('S', csv);
		if (kve[i].kve_flags & KVME_FLAG_GROWS_DOWN)
			fputc('D', csv);
		if (kve[i].kve_flags & KVME_FLAG_GROWS_UP)
			fputc('U', csv);
		fputs(", ", csv);
		switch (kve[i].kve_type) {
		case KVME_TYPE_NONE:
			fputs("none, ", csv);
			break;
		case KVME_TYPE_DEFAULT:
			fputs("default, ", csv);
			break;
		case KVME_TYPE_VNODE:
			fputs("vnode, ", csv);
			break;
		case KVME_TYPE_SWAP:
			fputs("swap, ", csv);
			break;
		case KVME_TYPE_DEVICE:
			fputs("device, ", csv);
			break;
		case KVME_TYPE_PHYS:
			fputs("physical, ", csv);
			break;
		case KVME_TYPE_DEAD:
			fputs("dead, ", csv);
			break;
		case KVME_TYPE_SG:
			fputs("scatter_gather, ", csv);
			break;
		case KVME_TYPE_MGTDEVICE:
			fputs("managed_device, ", csv);
			break;
		case KVME_TYPE_UNKNOWN:
			fputs("unknown, ", csv);
			break;
		}
		if (kve[i].kve_vn_type == VREG)
			fputs(kve[i].kve_path, csv);
		putc('\n', csv);
	}

	procstat_freeprocs(ps, kip);
	procstat_close(ps);
	fclose(csv);
}

int
main(int argc, char **argv)
{
	int status;
	pid_t pid;

	/* Adjust argc and argv as though we've used getopt. */
	argc--;
	argv++;

	if (argc == 0)
		usage();

	pid = fork();
	if (pid < 0)
		err(EX_OSERR, "fork");
	if (pid == 0) {
		if (ptrace(PT_TRACE_ME, 0, 0, 0))
			err(EX_OSERR, "ptrace trace_me");
		if (execvp(argv[0], argv) == -1)
			err(EX_OSERR, "execvp");
	}

	waitpid(pid, &status, 0);
	while (ptrace(PT_TO_SCE, pid, (caddr_t)1, 0) == 0) {
		waitpid(pid, &status, 0);
		if (WSTOPSIG(status) == SIGTRAP) {
			struct ptrace_lwpinfo lwpi;
			if (ptrace(PT_LWPINFO, pid, &lwpi, sizeof(lwpi)))
				err(EX_OSERR, "ptrace lwpinfo");
			if (lwpi.pl_flags & PL_FLAG_SCE &&
			    lwpi.pl_syscall_code == SYS_exit) {
				extract_vmap(pid);
				if (ptrace(PT_DETACH, pid, 0, 0))
					err(EX_OSERR, "ptrace detach");
				break;
			}
		}
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status)) {
		warnx("child exited abnormally");
		exit(-1);
	}
	exit(WEXITSTATUS(status));
}
