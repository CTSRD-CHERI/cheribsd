/*-
 * Copyright (c) 2020 Edward Tomasz Napierala <trasz@FreeBSD.org>
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

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

#ifdef __mips__

static const char *register_names[32] = {
	"zero", "at",   "v0",   "v1",   "a0",   "a1",   "a2",   "a3",
	"a4",   "a5",   "a6",   "a7",   "t0",   "t1",   "t2",   "t3",
	"s0",   "s1",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
	"t8",   "t9",   "k0",   "k1",   "gp",   "sp",   "s8",   "ra"
};

static void
log_stuff(FILE *fp, pid_t pid, const struct reg *thisreg, const struct reg *prevreg)
{
	int i, instr;

	errno = 0;
	/* 37 is pc: sys/mips/include/regnum.h */
	instr = ptrace(PT_READ_I, pid, (caddr_t)thisreg->r_regs[37], 0);
	if (errno != 0)
		err(1, "PT_READ_I");

	fprintf(fp, "%12lx:   %08x # ", thisreg->r_regs[37], instr);

	for (i = 0; (unsigned long)i < nitems(register_names); i++) {
		if (thisreg->r_regs[i] == prevreg->r_regs[i])
			continue;
		fprintf(fp, "%s := %#018lx ", register_names[i], thisreg->r_regs[i]);
	}

	fprintf(fp, "\n");
}

#else
#error "wrong architecture"
#endif

static void __dead2
usage(void)
{

	fprintf(stderr, "usage: slowtrace [-o output-path] binary-path [binary-args ...]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	FILE *output_fp;
	const char *path, *output_path = NULL;
	pid_t pid;
	int ch, error, status;
	struct reg regs[2], *thisreg, *prevreg, *tmpreg;

	while ((ch = getopt(argc, argv, "o:")) != -1) {
		switch (ch) {
		case 'o':
			output_path = optarg;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	path = argv[0];

	pid = fork();
	if (pid < 0)
		err(1, "fork");

	if (pid == 0) {
		error = ptrace(PT_TRACE_ME, 0, 0, 0);
		if (error != 0)
			err(1, "PT_TRACE_ME");

		error = execve(path, argv, environ);
		err(1, "%s", path);
	}

	if (output_path != NULL) {
		output_fp = fopen(output_path, "w");
		if (output_fp == NULL)
			err(1, "%s", output_path);
	} else {
		output_fp = stderr;
	}

	thisreg = &regs[0];
	prevreg = &regs[1];
	memset(thisreg, 0, sizeof(*thisreg));
	memset(prevreg, 0, sizeof(*prevreg));

	for (;;) {
		error = waitpid(pid, &status, WTRAPPED | WEXITED);
		if (error < 0)
			err(1, "waitpid");

		tmpreg = thisreg;
		thisreg = prevreg;
		prevreg = tmpreg;

		error = ptrace(PT_GETREGS, pid, (caddr_t)thisreg, 0);
		if (error != 0)
			err(1, "PT_GETREGS");

		log_stuff(output_fp, pid, thisreg, prevreg);

		error = ptrace(PT_STEP, pid, (caddr_t)1, 0);
		if (error != 0)
			err(1, "PT_STEP");
	}
}
