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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/kcov.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include "statcounters.h"

#if defined(__mips__)
#define STATCOUNTERS_ARCH_INC "statcounters_mips.inc"
#elif defined(__riscv)
#define STATCOUNTERS_ARCH_INC "statcounters_riscv.inc"
#else
#error "Unknown architecture"
#endif

#if defined(__mips__)
// low level rdhwr access to counters
//////////////////////////////////////////////////////////////////////////////

// TODO the itlbmiss/dtlbmiss/cycle/inst counters are not reset with that
static inline void resetStatCounters (void)
{
    __asm __volatile(".word (0x1F << 26) | (0x0 << 21) | (0x0 << 16) | (0x7 << 11) | (0x0 << 6) | (0x3B)");
}

#define STATCOUNTER_NAMES_MAX	128
#endif

static int statcounter_names_len = 0;

/* Build an array of statcounters without using __attribute__((constructor)): */
static struct {
	const char	*counter_name;
	uint64_t	(*counter_get)(void);
} statcounter_names[] = {
#define STATCOUNTER_ITEM(name, field, args)	\
    { __XSTRING(name), &statcounters_read_##field },
#include STATCOUNTERS_ARCH_INC
};

// helper functions

#define ARCHNAME_BUFF_SZ 32

static const char* getarchname(void)
{
    const char* result = "unknown_arch";
#if defined(__mips__)
#  if defined(__CHERI__)
#    define STATCOUNTERS_ARCH "cheri" __XSTRING(_MIPS_SZCAP)
#  else
#    define STATCOUNTERS_ARCH "mips"
#    if defined(__mips_n64)
#      define STATCOUNTERS_ABI "" /* n64 is default case -> no suffix */
#    elif defined(__mips_n32)
#      define STATCOUNTERS_ABI "-n32"
#    else
#      error "Unkown MIPS ABI"
#    endif
#  endif
#elif defined(__riscv)
#  define STATCOUNTERS_ARCH "riscv" __XSTRING(__riscv_xlen)
#else /* !defined(__mips__) */
#  error "Unknown target archicture for libstatcounters"
#endif
#if __has_feature(capabilities)
#  if defined(__CHERI_PURE_CAPABILITY__)
#    define STATCOUNTERS_ABI "-purecap"
#  else
#    define STATCOUNTERS_ABI "-hybrid"
#  endif
#else
#  define STATCOUNTERS_ABI ""
#endif
	result = STATCOUNTERS_ARCH STATCOUNTERS_ABI;
	return result;
}

// libstatcounters API
//////////////////////////////////////////////////////////////////////////////

#if defined(__mips__)
// reset the hardware statcounters
void reset_statcounters (void)
{
    statcounters_reset();
}
void statcounters_reset (void)
{
    resetStatCounters();
}
#endif

// zero a statcounters_bank
void zero_statcounters (statcounters_bank_t * const cnt_bank)
{
    statcounters_zero(cnt_bank);
}
int statcounters_zero (statcounters_bank_t * const cnt_bank)
{
    if (cnt_bank == NULL)
        return -1;
    memset(cnt_bank, 0, sizeof(statcounters_bank_t));
    return 0;
}

// sample hardware counters in a statcounters_bank
void sample_statcounters (statcounters_bank_t * const cnt_bank)
{
    statcounters_sample(cnt_bank);
}
int statcounters_sample (statcounters_bank_t * const cnt_bank)
{
    if (cnt_bank == NULL)
        return -1;

#define STATCOUNTER_ITEM(name, field, args) \
	cnt_bank->field = statcounters_read_##field();
#include STATCOUNTERS_ARCH_INC
    return 0;
}

/*
 * Sample statistics that require access via a sysctl
 */
int statcounters_sample_sysctl(statcounters_bank_t * const cnt_bank)
{
    int err;
    size_t len;

    if (cnt_bank == NULL)
        return (-1);
#ifdef __mips__
    err = sysctlbyname("machdep.kern_unaligned_access",
        &cnt_bank->kern_unaligned_access, &len, NULL, 0);
    if (err || len != sizeof(cnt_bank->kern_unaligned_access))
        return (-1);
#endif
    return (0);
}

// diff two statcounters_banks into a third one
void diff_statcounters (
    const statcounters_bank_t * const be,
    const statcounters_bank_t * const bs,
    statcounters_bank_t * const bd)
{
    statcounters_diff(bd,be,bs);
}
int statcounters_diff (
    statcounters_bank_t * const bd,
    const statcounters_bank_t * const be,
    const statcounters_bank_t * const bs)
{
    if (bd == NULL || be == NULL || bs == NULL)
        return -1;

#define STATCOUNTER_ITEM(name, field, args) bd->field = be->field - bs->field;
#include STATCOUNTERS_ARCH_INC
    return 0;
}

// dump a statcounters_bank in a file (csv or human readable)
void dump_statcounters (
    const statcounters_bank_t * const b,
    const char * const fname,
    const char * const fmt)
{
    /* XXXAR: a lot of this is duplicated from end_sample */
    FILE * fp = NULL;
    bool display_header = true;
    statcounters_fmt_flag_t flg = HUMAN_READABLE;
    if (!fname)
        return;
    if (access(fname, F_OK) != -1)
        display_header = false;
    if ((fp = fopen(fname, "a")))
    {
        if (fmt && (strcmp(fmt,"csv") == 0))
        {
            if (display_header) flg = CSV_HEADER;
            else flg = CSV_NOHEADER;
        }
        const char * pname = getenv("STATCOUNTERS_PROGNAME");
        if (!pname || pname[0] == '\0')
            pname = getprogname();
        const char * aname = getenv("STATCOUNTERS_ARCHNAME");
        if (!aname || aname[0] == '\0')
            aname = getarchname();
        statcounters_dump_with_args(b,pname,NULL,aname,fp,flg);
        fclose(fp);
    } else {
        warn("Failed to open statcounters output %s", fname);
    }
}
int statcounters_dump (const statcounters_bank_t * const b)
{
    return statcounters_dump_with_args(b,NULL,NULL,NULL,NULL,HUMAN_READABLE);
}
int statcounters_dump_with_phase (
    const statcounters_bank_t * const b,
    const char * phase)
{
    return statcounters_dump_with_args(b,NULL,phase,NULL,NULL,HUMAN_READABLE);
}
int statcounters_dump_with_args (
    const statcounters_bank_t * const b,
    const char * progname,
    const char * phase,
    const char * archname,
    FILE * const fileptr,
    const statcounters_fmt_flag_t format_flag)
{
    // preparing default values for NULL arguments
    // displayed progname
#define MAX_NAME_SIZE 512
    if (!progname) {
        progname = getenv("STATCOUNTERS_PROGNAME");
        if (!progname || progname[0] == '\0')
	    progname = getprogname();
    }
    size_t pname_s = strnlen(progname,MAX_NAME_SIZE);
    size_t phase_s = 0;
    if (phase) {
        phase_s = strnlen(phase,MAX_NAME_SIZE);
    }
    char * pname = malloc((sizeof(char) * (pname_s + phase_s)) + 1);
    strncpy(pname, progname, pname_s + 1);
    if (phase) {
        strncat(pname, phase, phase_s);
    }
    // displayed archname
    const char * aname;
    if (!archname) {
        aname = getenv("STATCOUNTERS_ARCHNAME");
        if (!aname || aname[0] == '\0')
            aname = getarchname();
    } else {
        aname = archname;
    }
    // dump file pointer
    bool display_header = true;
    bool use_stdout = false;
    FILE * fp = fileptr;
    if (!fp) {
        const char * const fname = getenv("STATCOUNTERS_OUTPUT");
        if (!fname || fname[0] == '\0') {
            use_stdout = true;
        } else {
            if (access(fname, F_OK) != -1) {
                display_header = false;
            }
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
    // output format
    const char * const fmt = getenv("STATCOUNTERS_FORMAT");
    statcounters_fmt_flag_t fmt_flg = format_flag;
    if (fmt && (strcmp(fmt,"csv") == 0)) {
       if (display_header)
           fmt_flg = CSV_HEADER;
       else
           fmt_flg = CSV_NOHEADER;
    }

    if (b == NULL || fp == NULL)
        return -1;
    switch (fmt_flg)
    {
        case CSV_HEADER:
            fputs("progname,archname"
#define STATCOUNTER_ITEM(name, field, args) "," #name
#include STATCOUNTERS_ARCH_INC
                  "\n", fp);
            // fallthrough
        case CSV_NOHEADER:
            fprintf(fp, "%s,%s"
#define STATCOUNTER_ITEM(name, field, args) ",%" PRId64
#include STATCOUNTERS_ARCH_INC
                    "\n", pname, aname
#define STATCOUNTER_ITEM(name, field, args) , b->field
#include STATCOUNTERS_ARCH_INC
                    );
            break;
        case HUMAN_READABLE:
        default:
            fprintf(fp, "===== %s -- %s =====\n",pname, aname);
#define STATCOUNTER_ITEM(name, field, args) \
            fprintf(fp, "%-15s %" PRId64 "\n", #name ":", b->field);
#define STATCOUNTERS_GROUP_END() fprintf(fp, "\n");
#include STATCOUNTERS_ARCH_INC
            break;
    }
    free(pname);
    if (!use_stdout)
        fclose(fp);
    return 0;
}

const char *statcounters_get_next_name (const char *name)
{
	int i;

	if (name == NULL)
		return (statcounter_names[0].counter_name);

	for (i = 0; i < statcounter_names_len; i++) {
		if (strcmp(statcounter_names[i].counter_name, name) == 0)
			break;
	}

	if (i == statcounter_names_len)
		return (NULL);

	return (statcounter_names[i + 1].counter_name);
}

int statcounters_id_from_name (const char *name)
{
	int i;

	for (i = 0; i < statcounter_names_len; i++) {
		if (strcmp(statcounter_names[i].counter_name, name) == 0)
			return (i);
	}

	return (-1);
}

uint64_t statcounters_sample_by_id (int id)
{

	return (statcounter_names[id].counter_get());
}

#ifndef STATCOUNTERS_NO_CTOR_DTOR
// KCov routines
//////////////////////////////////////////////////////////////////////////////

static const char *kcov_dev_path = "/dev/kcov";
static unsigned long *kcov_buffer;
static bool kcov_enable = false;
static int kcov_fd;

static void statcounters_kcov_setup()
{

	if (access(kcov_dev_path, R_OK | W_OK) == -1)
		return;
	if ((kcov_fd = open(kcov_dev_path, O_RDWR)) == -1)
		return;
	if (ioctl(kcov_fd, KIOSETBUFSIZE, KCOV_MAXENTRIES))
		close(kcov_fd);
	kcov_buffer = mmap(NULL, KCOV_MAXENTRIES * KCOV_ENTRY_SIZE,
			   PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0);
	if (kcov_buffer == MAP_FAILED)
		close(kcov_fd);

	if (ioctl(kcov_fd, KIOENABLE, KCOV_MODE_TRACE_PC)) {
		munmap(kcov_buffer, KCOV_MAXENTRIES * KCOV_ENTRY_SIZE);
		close(kcov_fd);
	}
	kcov_enable = true;
}

static void statcounters_kcov_teardown()
{
	unsigned long i, n;
	FILE *fp = stdout;

	if (ioctl(kcov_fd, KIODISABLE, 0))
		goto out;

	n = kcov_buffer[0];
	if (n + 2 > KCOV_MAXENTRIES)
		fprintf(stderr, "kcov buffer too small, some entries were dropped");
	const char * const fname = getenv("STATCOUNTERS_KCOV_OUTPUT");
	if (fname && fname[0] != '\0') {
		fp = fopen(fname, "a");
	}
	for (i = 1; i < n + 1; i++)
		fprintf(fp, "%lx\n", kcov_buffer[i]);
out:
	munmap(kcov_buffer, KCOV_MAXENTRIES * KCOV_ENTRY_SIZE);
	close(kcov_fd);
}

// C constructor / atexit interface
//////////////////////////////////////////////////////////////////////////////

static statcounters_bank_t start_cnt;
static statcounters_bank_t end_cnt;
static statcounters_bank_t diff_cnt;

static void end_sample (void);

__attribute__((constructor))
static void start_sample (void)
{
	const char * const kcov_config = getenv("STATCOUNTERS_KCOV");

	// registering exit function
	atexit(end_sample);
	if (kcov_config && (strcmp(kcov_config, "yes") == 0))
		statcounters_kcov_setup();
	// initial sampling
        statcounters_sample_sysctl(&start_cnt);
	statcounters_sample(&start_cnt);
}

//__attribute__((destructor)) static void end_sample (void)
static void end_sample (void)
{
	// final sampling
	statcounters_sample(&end_cnt); // TODO change the order of sampling to keep cycle sampled early
        statcounters_sample_sysctl(&end_cnt);
	// stop kernel coverage and dump results
	if (kcov_enable)
		statcounters_kcov_teardown();
	// compute difference between samples
	statcounters_diff(&diff_cnt, &end_cnt, &start_cnt);
	// dump the counters
	statcounters_dump(&diff_cnt);
}

#endif /* STATCOUNTERS_NO_CTOR_DTOR */
