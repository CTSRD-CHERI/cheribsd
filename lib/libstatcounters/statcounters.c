/*-
 * Copyright (c) 2016-2017 Alexandre Joannou
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
#include <sys/param.h>

#include <err.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "statcounters.h"

/* Build an array of statcounters without using __attribute__((constructor)): */
static struct {
	const char *counter_name;
	uint64_t (*counter_get)(void);
} statcounter_names[] = {
#define STATCOUNTER_ITEM(name, field, args) \
	{ __XSTRING(name), &statcounters_read_##field },
#include "statcounters_md.inc"
};

// helper functions

static const char *
getarchname(void)
{
	const char *result = "unknown_arch";
	result = STATCOUNTERS_ARCH STATCOUNTERS_ABI;
	return result;
}

// libstatcounters API
//////////////////////////////////////////////////////////////////////////////

// zero a statcounters_bank
int
statcounters_zero(statcounters_bank_t * const cnt_bank)
{
	if (cnt_bank == NULL)
		return -1;
	memset(cnt_bank, 0, sizeof(statcounters_bank_t));
	return 0;
}

// sample hardware counters in a statcounters_bank
int
statcounters_sample(statcounters_bank_t * const cnt_bank)
{
	if (cnt_bank == NULL)
		return -1;

#define STATCOUNTER_ITEM(name, field, args) \
	cnt_bank->field = statcounters_read_##field();
#include "statcounters_md.inc"
	return 0;
}

// diff two statcounters_banks into a third one
int
statcounters_diff(statcounters_bank_t * const bd,
    const statcounters_bank_t * const be, const statcounters_bank_t * const bs)
{
	if (bd == NULL || be == NULL || bs == NULL)
		return -1;

#define STATCOUNTER_ITEM(name, field, args) bd->field = be->field - bs->field;
#include "statcounters_md.inc"
	return 0;
}

// dump a statcounters_bank in a file (csv or human readable)
int
statcounters_dump(const statcounters_bank_t * const b)
{
	return statcounters_dump_with_args(b, NULL, NULL, NULL, NULL,
	    HUMAN_READABLE);
}

int
statcounters_dump_with_phase(const statcounters_bank_t * const b,
    const char *phase)
{
	return statcounters_dump_with_args(b, NULL, phase, NULL, NULL,
	    HUMAN_READABLE);
}

int
statcounters_dump_with_args(const statcounters_bank_t * const b,
    const char *progname, const char *phase, const char *archname,
    FILE * const fileptr, const statcounters_fmt_flag_t format_flag)
{
	// preparing default values for NULL arguments
	if (!progname) {
		// displayed progname
		progname = getenv("STATCOUNTERS_PROGNAME");
		if (!progname || progname[0] == '\0')
			progname = getprogname();
	}
	if (!phase)
	    phase = "";
	// displayed archname
	if (!archname) {
		archname = getenv("STATCOUNTERS_ARCHNAME");
		if (!archname || archname[0] == '\0')
			archname = getarchname();
	}
	// dump file pointer
	bool display_header = true;
	bool use_stdout = false;
	FILE *fp = fileptr;
	if (!fp) {
		const char * const fname = getenv("STATCOUNTERS_OUTPUT");
		if (!fname || fname[0] == '\0') {
			use_stdout = true;
		} else {
			fp = fopen(fname, "a");
		}
		if (!fp && !use_stdout) {
			warn("Failed to open statcounters output %s", fname);
			use_stdout = true;
		}
	} else {
		use_stdout = false;
	}
	if (use_stdout)
		fp = stdout;
	// If there is already data in the output file, don't print the CSV
	// header again.
	if (ftello(fp) > 0) {
		display_header = false;
	}
	// output format
	const char * const fmt = getenv("STATCOUNTERS_FORMAT");
	statcounters_fmt_flag_t fmt_flg = format_flag;
	if (fmt && (strcmp(fmt, "csv") == 0)) {
		if (display_header)
			fmt_flg = CSV_HEADER;
		else
			fmt_flg = CSV_NOHEADER;
	}

	if (b == NULL || fp == NULL)
		return -1;
	switch (fmt_flg) {
	case CSV_HEADER:
		fputs("progname,archname"
#define STATCOUNTER_ITEM(name, field, args) "," #name
#include "statcounters_md.inc"
		      "\n",
		    fp);
		// fallthrough
	case CSV_NOHEADER:
		fprintf(fp,
		    "%s%s,%s"
#define STATCOUNTER_ITEM(name, field, args) ",%" PRId64
#include "statcounters_md.inc"
		    "\n",
		    progname, phase, archname
#define STATCOUNTER_ITEM(name, field, args) , b->field
#include "statcounters_md.inc"
		);
		break;
	case HUMAN_READABLE:
	default:
		fprintf(fp, "===== %s%s -- %s =====\n", progname, phase,
		    archname);
#define STATCOUNTER_ITEM(name, field, args) \
	fprintf(fp, "%-15s %" PRId64 "\n", #name ":", b->field);
#define STATCOUNTERS_GROUP_END() fprintf(fp, "\n");
#include "statcounters_md.inc"
		break;
	}
	if (!use_stdout && fileptr == NULL)
		fclose(fp);
	return 0;
}

const char *
statcounters_get_next_name(const char *name)
{
	size_t i;

	if (name == NULL)
		return (statcounter_names[0].counter_name);

	for (i = 0; i < nitems(statcounter_names); i++) {
		if (strcmp(statcounter_names[i].counter_name, name) == 0)
			break;
	}

	if (i == nitems(statcounter_names))
		return (NULL);

	return (statcounter_names[i + 1].counter_name);
}

int
statcounters_id_from_name(const char *name)
{
	size_t i;

	for (i = 0; i < nitems(statcounter_names); i++) {
		if (strcmp(statcounter_names[i].counter_name, name) == 0)
			return (i);
	}

	return (-1);
}

uint64_t
statcounters_sample_by_id(int id)
{
	if (id < 0 || (size_t)id > nitems(statcounter_names))
		return (-1);

	return (statcounter_names[id].counter_get());
}

#ifndef STATCOUNTERS_NO_CTOR_DTOR

// C constructor / atexit interface
//////////////////////////////////////////////////////////////////////////////

static statcounters_bank_t start_cnt;
static statcounters_bank_t end_cnt;
static statcounters_bank_t diff_cnt;

static void end_sample(void);

__attribute__((constructor)) static void
start_sample(void)
{
	const char *no_autosample = getenv("STATCOUNTERS_NO_AUTOSAMPLE");

	if (no_autosample && no_autosample[0] != '\0' &&
	    strtol(no_autosample, NULL, 0) != 0)
		return;

	// registering exit function
	atexit(end_sample);
	// initial sampling
	statcounters_sample(&start_cnt);
}

//__attribute__((destructor)) static void end_sample (void)
static void
end_sample(void)
{
	// final sampling
	statcounters_sample(&end_cnt); // TODO change the order of sampling to
				       // keep cycle sampled early
	// compute difference between samples
	statcounters_diff(&diff_cnt, &end_cnt, &start_cnt);
	// dump the counters
	statcounters_dump(&diff_cnt);
}

#endif /* STATCOUNTERS_NO_CTOR_DTOR */
