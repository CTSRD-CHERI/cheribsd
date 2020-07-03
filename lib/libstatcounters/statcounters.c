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

// low level rdhwr access to counters
//////////////////////////////////////////////////////////////////////////////

// TODO the itlbmiss/dtlbmiss/cycle/inst counters are not reset with that
static inline void resetStatCounters (void)
{
    __asm __volatile(".word (0x1F << 26) | (0x0 << 21) | (0x0 << 16) | (0x7 << 11) | (0x0 << 6) | (0x3B)");
}

#define STATCOUNTER_NAMES_MAX	128

static int statcounter_names_len = 0;

/* Declare all the statcounters accessor functions: */
#ifdef __mips__
#include "statcounters_mips.h"
#else
#error "Unsupported architecture!"
#endif

/* Build an array of statcounters without using __attribute__((constructor)): */
static struct {
	const char	*counter_name;
	uint64_t	(*counter_get)(void);
} statcounter_names[STATCOUNTER_NAMES_MAX] = {
#define STATCOUNTER_ITEM(name, X, Y)	\
    { __XSTRING(name), &statcounters_get_##name##_count },
#ifdef __mips__
#include "statcounters_mips.inc"
#else
#error "Unsupported architecture!"
#endif
#undef STATCOUNTER_ITEM
};


// available modules, module type, associated rdhw primary selector
//----------------------------------------------------------------------------
// instruction cache, CacheCore, 8
// data cache, CacheCore, 9
// level 2 cache, CacheCore, 10
// memory operations, MIPSMem, 11
// tag cache, CacheCore, 12
// level 2 cache master, MasterStats, 13
// tag cache master, MasterStats, 14

// module type : CacheCore
// available counter, associated rdhwr secondary selector
//----------------------------------------------------------------------------
// write hit, 0
// write miss, 1
// read hit, 2
// read miss, 3
// prefetch hit, 4
// prefetch miss, 5
// eviction, 6
// eviction due to prefetch, 7
// write of tag set, 8
// read of tag set, 9
enum
{
    STATCOUNTERS_WRITE_HIT     = 0,
    STATCOUNTERS_WRITE_MISS    = 1,
    STATCOUNTERS_READ_HIT      = 2,
    STATCOUNTERS_READ_MISS     = 3,
    STATCOUNTERS_PFTCH_HIT     = 4,
    STATCOUNTERS_PFTCH_MISS    = 5,
    STATCOUNTERS_EVICT         = 6,
    STATCOUNTERS_PFTCH_EVICT   = 7,
    STATCOUNTERS_SET_TAG_WRITE = 8,
    STATCOUNTERS_SET_TAG_READ  = 9
};
//----------------------------------------------------------------------------
// module type : MIPSMem
// available counter, associated rdhwr secondary selector
//----------------------------------------------------------------------------
// byte read, 0
// byte write, 1
// half word read, 2
// half word write, 3
// word read, 4
// word write, 5
// double word read, 6
// double word write, 7
// capability read, 8
// capability write, 9
enum
{
    STATCOUNTERS_BYTE_READ         = 0,
    STATCOUNTERS_BYTE_WRITE        = 1,
    STATCOUNTERS_HWORD_READ        = 2,
    STATCOUNTERS_HWORD_WRITE       = 3,
    STATCOUNTERS_WORD_READ         = 4,
    STATCOUNTERS_WORD_WRITE        = 5,
    STATCOUNTERS_DWORD_READ        = 6,
    STATCOUNTERS_DWORD_WRITE       = 7,
    STATCOUNTERS_CAP_READ          = 8,
    STATCOUNTERS_CAP_WRITE         = 9,
    STATCOUNTERS_CAP_READ_TAG_SET  = 10,
    STATCOUNTERS_CAP_WRITE_TAG_SET = 11
};
//----------------------------------------------------------------------------
// module type : MasterStats
// available counter, associated rdhwr secondary selector
//----------------------------------------------------------------------------
// read request, 0
// write request, 1
// write request flit, 2
// read response, 3
// read response flit, 4
// write response, 5
enum
{
    STATCOUNTERS_READ_REQ       = 0,
    STATCOUNTERS_WRITE_REQ      = 1,
    STATCOUNTERS_WRITE_REQ_FLIT = 2,
    STATCOUNTERS_READ_RSP       = 3,
    STATCOUNTERS_READ_RSP_FLIT  = 4,
    STATCOUNTERS_WRITE_RSP      = 5
};

// helper functions

#define ARCHNAME_BUFF_SZ 32

static const char* getarchname(void)
{
    const char* result = "unknown_arch";
#ifdef __mips__
#  if defined(__CHERI__)
#    define STATCOUNTERS_ARCH "cheri" __XSTRING(_MIPS_SZCAP)
#    if defined(__CHERI_PURE_CAPABILITY__)
#      define STATCOUNTERS_ABI "-purecap"
#    else
#      define STATCOUNTERS_ABI "-hybrid"
#    endif
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
    result = STATCOUNTERS_ARCH STATCOUNTERS_ABI;
#else /* !defined(__mips__) */
#  error "Unknown target archicture for libstatcounters"
#endif
    return result;
}

// libstatcounters API
//////////////////////////////////////////////////////////////////////////////

// reset the hardware statcounters
void reset_statcounters (void)
{
    statcounters_reset();
}
void statcounters_reset (void)
{
    resetStatCounters();
}

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
    cnt_bank->icache[STATCOUNTERS_WRITE_HIT]              = statcounters_get_icache_write_hit_count();
    cnt_bank->icache[STATCOUNTERS_WRITE_MISS]             = statcounters_get_icache_write_miss_count();
    cnt_bank->icache[STATCOUNTERS_READ_HIT]               = statcounters_get_icache_read_hit_count();
    cnt_bank->icache[STATCOUNTERS_READ_MISS]              = statcounters_get_icache_read_miss_count();
    cnt_bank->icache[STATCOUNTERS_EVICT]                  = statcounters_get_icache_evict_count();
    cnt_bank->dcache[STATCOUNTERS_WRITE_HIT]              = statcounters_get_dcache_write_hit_count();
    cnt_bank->dcache[STATCOUNTERS_WRITE_MISS]             = statcounters_get_dcache_write_miss_count();
    cnt_bank->dcache[STATCOUNTERS_READ_HIT]               = statcounters_get_dcache_read_hit_count();
    cnt_bank->dcache[STATCOUNTERS_READ_MISS]              = statcounters_get_dcache_read_miss_count();
    cnt_bank->dcache[STATCOUNTERS_EVICT]                  = statcounters_get_dcache_evict_count();
    cnt_bank->dcache[STATCOUNTERS_SET_TAG_WRITE]          = statcounters_get_dcache_set_tag_write_count();
    cnt_bank->dcache[STATCOUNTERS_SET_TAG_READ]           = statcounters_get_dcache_set_tag_read_count();
    cnt_bank->l2cache[STATCOUNTERS_WRITE_HIT]             = statcounters_get_l2cache_write_hit_count();
    cnt_bank->l2cache[STATCOUNTERS_WRITE_MISS]            = statcounters_get_l2cache_write_miss_count();
    cnt_bank->l2cache[STATCOUNTERS_READ_HIT]              = statcounters_get_l2cache_read_hit_count();
    cnt_bank->l2cache[STATCOUNTERS_READ_MISS]             = statcounters_get_l2cache_read_miss_count();
    cnt_bank->l2cache[STATCOUNTERS_EVICT]                 = statcounters_get_l2cache_evict_count();
    cnt_bank->l2cache[STATCOUNTERS_SET_TAG_WRITE]         = statcounters_get_l2cache_set_tag_write_count();
    cnt_bank->l2cache[STATCOUNTERS_SET_TAG_READ]          = statcounters_get_l2cache_set_tag_read_count();
    cnt_bank->l2cachemaster[STATCOUNTERS_READ_REQ]        = statcounters_get_l2cachemaster_read_req_count();
    cnt_bank->l2cachemaster[STATCOUNTERS_WRITE_REQ]       = statcounters_get_l2cachemaster_write_req_count();
    cnt_bank->l2cachemaster[STATCOUNTERS_WRITE_REQ_FLIT]  = statcounters_get_l2cachemaster_write_req_flit_count();
    cnt_bank->l2cachemaster[STATCOUNTERS_READ_RSP]        = statcounters_get_l2cachemaster_read_rsp_count();
    cnt_bank->l2cachemaster[STATCOUNTERS_READ_RSP_FLIT]   = statcounters_get_l2cachemaster_read_rsp_flit_count();
    cnt_bank->l2cachemaster[STATCOUNTERS_WRITE_RSP]       = statcounters_get_l2cachemaster_write_rsp_count();
    cnt_bank->tagcache[STATCOUNTERS_WRITE_HIT]            = statcounters_get_tagcache_write_hit_count();
    cnt_bank->tagcache[STATCOUNTERS_WRITE_MISS]           = statcounters_get_tagcache_write_miss_count();
    cnt_bank->tagcache[STATCOUNTERS_READ_HIT]             = statcounters_get_tagcache_read_hit_count();
    cnt_bank->tagcache[STATCOUNTERS_READ_MISS]            = statcounters_get_tagcache_read_miss_count();
    cnt_bank->tagcache[STATCOUNTERS_EVICT]                = statcounters_get_tagcache_evict_count();
    cnt_bank->tagcachemaster[STATCOUNTERS_READ_REQ]       = statcounters_get_tagcachemaster_read_req_count();
    cnt_bank->tagcachemaster[STATCOUNTERS_WRITE_REQ]      = statcounters_get_tagcachemaster_write_req_count();
    cnt_bank->tagcachemaster[STATCOUNTERS_WRITE_REQ_FLIT] = statcounters_get_tagcachemaster_write_req_flit_count();
    cnt_bank->tagcachemaster[STATCOUNTERS_READ_RSP]       = statcounters_get_tagcachemaster_read_rsp_count();
    cnt_bank->tagcachemaster[STATCOUNTERS_READ_RSP_FLIT]  = statcounters_get_tagcachemaster_read_rsp_flit_count();
    cnt_bank->tagcachemaster[STATCOUNTERS_WRITE_RSP]      = statcounters_get_tagcachemaster_write_rsp_count();
    cnt_bank->mipsmem[STATCOUNTERS_BYTE_READ]             = statcounters_get_mem_byte_read_count();
    cnt_bank->mipsmem[STATCOUNTERS_BYTE_WRITE]            = statcounters_get_mem_byte_write_count();
    cnt_bank->mipsmem[STATCOUNTERS_HWORD_READ]            = statcounters_get_mem_hword_read_count();
    cnt_bank->mipsmem[STATCOUNTERS_HWORD_WRITE]           = statcounters_get_mem_hword_write_count();
    cnt_bank->mipsmem[STATCOUNTERS_WORD_READ]             = statcounters_get_mem_word_read_count();
    cnt_bank->mipsmem[STATCOUNTERS_WORD_WRITE]            = statcounters_get_mem_word_write_count();
    cnt_bank->mipsmem[STATCOUNTERS_DWORD_READ]            = statcounters_get_mem_dword_read_count();
    cnt_bank->mipsmem[STATCOUNTERS_DWORD_WRITE]           = statcounters_get_mem_dword_write_count();
    cnt_bank->mipsmem[STATCOUNTERS_CAP_READ]              = statcounters_get_mem_cap_read_count();
    cnt_bank->mipsmem[STATCOUNTERS_CAP_WRITE]             = statcounters_get_mem_cap_write_count();
    cnt_bank->mipsmem[STATCOUNTERS_CAP_READ_TAG_SET]      = statcounters_get_mem_cap_read_tag_set_count();
    cnt_bank->mipsmem[STATCOUNTERS_CAP_WRITE_TAG_SET]     = statcounters_get_mem_cap_write_tag_set_count();
    cnt_bank->dtlb_miss                                   = statcounters_get_dtlb_miss_count();
    cnt_bank->itlb_miss                                   = statcounters_get_itlb_miss_count();
    cnt_bank->inst                                        = statcounters_get_inst_count();
    cnt_bank->inst_user                                   = statcounters_get_inst_user_count();
    cnt_bank->inst_kernel                                 = statcounters_get_inst_kernel_count();
    cnt_bank->imprecise_setbounds                         = statcounters_get_imprecise_setbounds_count();
    cnt_bank->unrepresentable_caps                        = statcounters_get_unrepresentable_caps_count();
    cnt_bank->cycle                                       = statcounters_get_cycle_count();
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
    bd->itlb_miss    = be->itlb_miss - bs->itlb_miss;
    bd->dtlb_miss    = be->dtlb_miss - bs->dtlb_miss;
    bd->cycle        = be->cycle - bs->cycle;
    bd->inst         = be->inst - bs->inst;
    bd->inst_user    = be->inst_user - bs->inst_user;
    bd->inst_kernel  = be->inst_kernel - bs->inst_kernel;
    bd->imprecise_setbounds = be->imprecise_setbounds - bs->imprecise_setbounds;
    bd->unrepresentable_caps = be->unrepresentable_caps - bs->unrepresentable_caps;
    for (int i = 0; i < STATCOUNTERS_MAX_MOD_CNT; i++)
    {
        bd->icache[i]         = be->icache[i] - bs->icache[i];
        bd->dcache[i]         = be->dcache[i] - bs->dcache[i];
        bd->l2cache[i]        = be->l2cache[i] - bs->l2cache[i];
        bd->mipsmem[i]        = be->mipsmem[i] - bs->mipsmem[i];
        bd->tagcache[i]       = be->tagcache[i] - bs->tagcache[i];
        bd->l2cachemaster[i]  = be->l2cachemaster[i] - bs->l2cachemaster[i];
        bd->tagcachemaster[i] = be->tagcachemaster[i] - bs->tagcachemaster[i];
    }
    bd->kern_unaligned_access = be->kern_unaligned_access - bs->kern_unaligned_access;
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
            fprintf(fp, "progname,");
            fprintf(fp, "archname,");
            fprintf(fp, "cycles,");
            fprintf(fp, "instructions,");
            fprintf(fp, "inst_user,");
            fprintf(fp, "inst_kernel,");
            fprintf(fp, "itlb_miss,");
            fprintf(fp, "dtlb_miss,");
            fprintf(fp, "icache_write_hit,");
            fprintf(fp, "icache_write_miss,");
            fprintf(fp, "icache_read_hit,");
            fprintf(fp, "icache_read_miss,");
            fprintf(fp, "icache_evict,");
            fprintf(fp, "dcache_write_hit,");
            fprintf(fp, "dcache_write_miss,");
            fprintf(fp, "dcache_read_hit,");
            fprintf(fp, "dcache_read_miss,");
            fprintf(fp, "dcache_evict,");
            fprintf(fp, "dcache_set_tag_write,");
            fprintf(fp, "dcache_set_tag_read,");
            fprintf(fp, "l2cache_write_hit,");
            fprintf(fp, "l2cache_write_miss,");
            fprintf(fp, "l2cache_read_hit,");
            fprintf(fp, "l2cache_read_miss,");
            fprintf(fp, "l2cache_evict,");
            fprintf(fp, "l2cache_set_tag_write,");
            fprintf(fp, "l2cache_set_tag_read,");
            fprintf(fp, "tagcache_write_hit,");
            fprintf(fp, "tagcache_write_miss,");
            fprintf(fp, "tagcache_read_hit,");
            fprintf(fp, "tagcache_read_miss,");
            fprintf(fp, "tagcache_evict,");
            fprintf(fp, "mipsmem_byte_read,");
            fprintf(fp, "mipsmem_byte_write,");
            fprintf(fp, "mipsmem_hword_read,");
            fprintf(fp, "mipsmem_hword_write,");
            fprintf(fp, "mipsmem_word_read,");
            fprintf(fp, "mipsmem_word_write,");
            fprintf(fp, "mipsmem_dword_read,");
            fprintf(fp, "mipsmem_dword_write,");
            fprintf(fp, "mipsmem_cap_read,");
            fprintf(fp, "mipsmem_cap_write,");
            fprintf(fp, "mipsmem_cap_read_tag_set,");
            fprintf(fp, "mipsmem_cap_write_tag_set,");
            fprintf(fp, "l2cachemaster_read_req,");
            fprintf(fp, "l2cachemaster_write_req,");
            fprintf(fp, "l2cachemaster_write_req_flit,");
            fprintf(fp, "l2cachemaster_read_rsp,");
            fprintf(fp, "l2cachemaster_read_rsp_flit,");
            fprintf(fp, "l2cachemaster_write_rsp,");
            fprintf(fp, "tagcachemaster_read_req,");
            fprintf(fp, "tagcachemaster_write_req,");
            fprintf(fp, "tagcachemaster_write_req_flit,");
            fprintf(fp, "tagcachemaster_read_rsp,");
            fprintf(fp, "tagcachemaster_read_rsp_flit,");
            fprintf(fp, "tagcachemaster_write_rsp,");
            fprintf(fp, "imprecise_setbounds,");
            fprintf(fp, "unrepresentable_caps");
            fprintf(fp, "kern_unaligned_access");
            fprintf(fp, "\n");
            // fallthrough
        case CSV_NOHEADER:
            fprintf(fp, "%s,",pname);
            fprintf(fp, "%s,",aname);
            fprintf(fp, "%lu,",b->cycle);
            fprintf(fp, "%lu,",b->inst);
            fprintf(fp, "%lu,",b->inst_user);
            fprintf(fp, "%lu,",b->inst_kernel);
            fprintf(fp, "%lu,",b->itlb_miss);
            fprintf(fp, "%lu,",b->dtlb_miss);
            fprintf(fp, "%lu,",b->icache[STATCOUNTERS_WRITE_HIT]);
            fprintf(fp, "%lu,",b->icache[STATCOUNTERS_WRITE_MISS]);
            fprintf(fp, "%lu,",b->icache[STATCOUNTERS_READ_HIT]);
            fprintf(fp, "%lu,",b->icache[STATCOUNTERS_READ_MISS]);
            fprintf(fp, "%lu,",b->icache[STATCOUNTERS_EVICT]);
            fprintf(fp, "%lu,",b->dcache[STATCOUNTERS_WRITE_HIT]);
            fprintf(fp, "%lu,",b->dcache[STATCOUNTERS_WRITE_MISS]);
            fprintf(fp, "%lu,",b->dcache[STATCOUNTERS_READ_HIT]);
            fprintf(fp, "%lu,",b->dcache[STATCOUNTERS_READ_MISS]);
            fprintf(fp, "%lu,",b->dcache[STATCOUNTERS_EVICT]);
            fprintf(fp, "%lu,",b->dcache[STATCOUNTERS_SET_TAG_WRITE]);
            fprintf(fp, "%lu,",b->dcache[STATCOUNTERS_SET_TAG_READ]);
            fprintf(fp, "%lu,",b->l2cache[STATCOUNTERS_WRITE_HIT]);
            fprintf(fp, "%lu,",b->l2cache[STATCOUNTERS_WRITE_MISS]);
            fprintf(fp, "%lu,",b->l2cache[STATCOUNTERS_READ_HIT]);
            fprintf(fp, "%lu,",b->l2cache[STATCOUNTERS_READ_MISS]);
            fprintf(fp, "%lu,",b->l2cache[STATCOUNTERS_EVICT]);
            fprintf(fp, "%lu,",b->l2cache[STATCOUNTERS_SET_TAG_WRITE]);
            fprintf(fp, "%lu,",b->l2cache[STATCOUNTERS_SET_TAG_READ]);
            fprintf(fp, "%lu,",b->tagcache[STATCOUNTERS_WRITE_HIT]);
            fprintf(fp, "%lu,",b->tagcache[STATCOUNTERS_WRITE_MISS]);
            fprintf(fp, "%lu,",b->tagcache[STATCOUNTERS_READ_HIT]);
            fprintf(fp, "%lu,",b->tagcache[STATCOUNTERS_READ_MISS]);
            fprintf(fp, "%lu,",b->tagcache[STATCOUNTERS_EVICT]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_BYTE_READ]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_BYTE_WRITE]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_HWORD_READ]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_HWORD_WRITE]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_WORD_READ]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_WORD_WRITE]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_DWORD_READ]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_DWORD_WRITE]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_CAP_READ]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_CAP_WRITE]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_CAP_READ_TAG_SET]);
            fprintf(fp, "%lu,",b->mipsmem[STATCOUNTERS_CAP_WRITE_TAG_SET]);
            fprintf(fp, "%lu,",b->l2cachemaster[STATCOUNTERS_READ_REQ]);
            fprintf(fp, "%lu,",b->l2cachemaster[STATCOUNTERS_WRITE_REQ]);
            fprintf(fp, "%lu,",b->l2cachemaster[STATCOUNTERS_WRITE_REQ_FLIT]);
            fprintf(fp, "%lu,",b->l2cachemaster[STATCOUNTERS_READ_RSP]);
            fprintf(fp, "%lu,",b->l2cachemaster[STATCOUNTERS_READ_RSP_FLIT]);
            fprintf(fp, "%lu,",b->l2cachemaster[STATCOUNTERS_WRITE_RSP]);
            fprintf(fp, "%lu,",b->tagcachemaster[STATCOUNTERS_READ_REQ]);
            fprintf(fp, "%lu,",b->tagcachemaster[STATCOUNTERS_WRITE_REQ]);
            fprintf(fp, "%lu,",b->tagcachemaster[STATCOUNTERS_WRITE_REQ_FLIT]);
            fprintf(fp, "%lu,",b->tagcachemaster[STATCOUNTERS_READ_RSP]);
            fprintf(fp, "%lu,",b->tagcachemaster[STATCOUNTERS_READ_RSP_FLIT]);
            fprintf(fp, "%lu,",b->tagcachemaster[STATCOUNTERS_WRITE_RSP]);
            fprintf(fp, "%lu,",b->imprecise_setbounds);
            fprintf(fp, "%lu",b->unrepresentable_caps);
            fprintf(fp, "%lu",b->kern_unaligned_access);
            fprintf(fp, "\n");
            break;
        case HUMAN_READABLE:
        default:
            fprintf(fp, "===== %s -- %s =====\n",pname, aname);
            fprintf(fp, "cycles:                       \t%lu\n",b->cycle);
            fprintf(fp, "instructions:                 \t%lu\n",b->inst);
            fprintf(fp, "instructions (user):          \t%lu\n",b->inst_user);
            fprintf(fp, "instructions (kernel):        \t%lu\n",b->inst_kernel);
            fprintf(fp, "itlb_miss:                    \t%lu\n",b->itlb_miss);
            fprintf(fp, "dtlb_miss:                    \t%lu\n",b->dtlb_miss);
            fprintf(fp, "\n");
            fprintf(fp, "icache_write_hit:             \t%lu\n",b->icache[STATCOUNTERS_WRITE_HIT]);
            fprintf(fp, "icache_write_miss:            \t%lu\n",b->icache[STATCOUNTERS_WRITE_MISS]);
            fprintf(fp, "icache_read_hit:              \t%lu\n",b->icache[STATCOUNTERS_READ_HIT]);
            fprintf(fp, "icache_read_miss:             \t%lu\n",b->icache[STATCOUNTERS_READ_MISS]);
            fprintf(fp, "icache_evict:                 \t%lu\n",b->icache[STATCOUNTERS_EVICT]);
            fprintf(fp, "\n");
            fprintf(fp, "dcache_write_hit:             \t%lu\n",b->dcache[STATCOUNTERS_WRITE_HIT]);
            fprintf(fp, "dcache_write_miss:            \t%lu\n",b->dcache[STATCOUNTERS_WRITE_MISS]);
            fprintf(fp, "dcache_read_hit:              \t%lu\n",b->dcache[STATCOUNTERS_READ_HIT]);
            fprintf(fp, "dcache_read_miss:             \t%lu\n",b->dcache[STATCOUNTERS_READ_MISS]);
            fprintf(fp, "dcache_evict:                 \t%lu\n",b->dcache[STATCOUNTERS_EVICT]);
            fprintf(fp, "dcache_set_tag_write:         \t%lu\n",b->dcache[STATCOUNTERS_SET_TAG_WRITE]);
            fprintf(fp, "dcache_set_tag_read:          \t%lu\n",b->dcache[STATCOUNTERS_SET_TAG_READ]);
            fprintf(fp, "\n");
            fprintf(fp, "l2cache_write_hit:            \t%lu\n",b->l2cache[STATCOUNTERS_WRITE_HIT]);
            fprintf(fp, "l2cache_write_miss:           \t%lu\n",b->l2cache[STATCOUNTERS_WRITE_MISS]);
            fprintf(fp, "l2cache_read_hit:             \t%lu\n",b->l2cache[STATCOUNTERS_READ_HIT]);
            fprintf(fp, "l2cache_read_miss:            \t%lu\n",b->l2cache[STATCOUNTERS_READ_MISS]);
            fprintf(fp, "l2cache_evict:                \t%lu\n",b->l2cache[STATCOUNTERS_EVICT]);
            fprintf(fp, "l2cache_set_tag_write:        \t%lu\n",b->l2cache[STATCOUNTERS_SET_TAG_WRITE]);
            fprintf(fp, "l2cache_set_tag_read:         \t%lu\n",b->l2cache[STATCOUNTERS_SET_TAG_READ]);
            fprintf(fp, "\n");
            fprintf(fp, "tagcache_write_hit:           \t%lu\n",b->tagcache[STATCOUNTERS_WRITE_HIT]);
            fprintf(fp, "tagcache_write_miss:          \t%lu\n",b->tagcache[STATCOUNTERS_WRITE_MISS]);
            fprintf(fp, "tagcache_read_hit:            \t%lu\n",b->tagcache[STATCOUNTERS_READ_HIT]);
            fprintf(fp, "tagcache_read_miss:           \t%lu\n",b->tagcache[STATCOUNTERS_READ_MISS]);
            fprintf(fp, "tagcache_evict:               \t%lu\n",b->tagcache[STATCOUNTERS_EVICT]);
            fprintf(fp, "\n");
            fprintf(fp, "mem_byte_read:                \t%lu\n",b->mipsmem[STATCOUNTERS_BYTE_READ]);
            fprintf(fp, "mem_byte_write:               \t%lu\n",b->mipsmem[STATCOUNTERS_BYTE_WRITE]);
            fprintf(fp, "mem_hword_read:               \t%lu\n",b->mipsmem[STATCOUNTERS_HWORD_READ]);
            fprintf(fp, "mem_hword_write:              \t%lu\n",b->mipsmem[STATCOUNTERS_HWORD_WRITE]);
            fprintf(fp, "mem_word_read:                \t%lu\n",b->mipsmem[STATCOUNTERS_WORD_READ]);
            fprintf(fp, "mem_word_write:               \t%lu\n",b->mipsmem[STATCOUNTERS_WORD_WRITE]);
            fprintf(fp, "mem_dword_read:               \t%lu\n",b->mipsmem[STATCOUNTERS_DWORD_READ]);
            fprintf(fp, "mem_dword_write:              \t%lu\n",b->mipsmem[STATCOUNTERS_DWORD_WRITE]);
            fprintf(fp, "mem_cap_read:                 \t%lu\n",b->mipsmem[STATCOUNTERS_CAP_READ]);
            fprintf(fp, "mem_cap_write:                \t%lu\n",b->mipsmem[STATCOUNTERS_CAP_WRITE]);
            fprintf(fp, "mem_cap_read_tag_set:         \t%lu\n",b->mipsmem[STATCOUNTERS_CAP_READ_TAG_SET]);
            fprintf(fp, "mem_cap_write_tag_set:        \t%lu\n",b->mipsmem[STATCOUNTERS_CAP_WRITE_TAG_SET]);
            fprintf(fp, "\n");
            fprintf(fp, "l2cachemaster_read_req:       \t%lu\n",b->l2cachemaster[STATCOUNTERS_READ_REQ]);
            fprintf(fp, "l2cachemaster_write_req:      \t%lu\n",b->l2cachemaster[STATCOUNTERS_WRITE_REQ]);
            fprintf(fp, "l2cachemaster_write_req_flit: \t%lu\n",b->l2cachemaster[STATCOUNTERS_WRITE_REQ_FLIT]);
            fprintf(fp, "l2cachemaster_read_rsp:       \t%lu\n",b->l2cachemaster[STATCOUNTERS_READ_RSP]);
            fprintf(fp, "l2cachemaster_read_rsp_flit:  \t%lu\n",b->l2cachemaster[STATCOUNTERS_READ_RSP_FLIT]);
            fprintf(fp, "l2cachemaster_write_rsp:      \t%lu\n",b->l2cachemaster[STATCOUNTERS_WRITE_RSP]);
            fprintf(fp, "\n");
            fprintf(fp, "tagcachemaster_read_req:      \t%lu\n",b->tagcachemaster[STATCOUNTERS_READ_REQ]);
            fprintf(fp, "tagcachemaster_write_req:     \t%lu\n",b->tagcachemaster[STATCOUNTERS_WRITE_REQ]);
            fprintf(fp, "tagcachemaster_write_req_flit:\t%lu\n",b->tagcachemaster[STATCOUNTERS_WRITE_REQ_FLIT]);
            fprintf(fp, "tagcachemaster_read_rsp:      \t%lu\n",b->tagcachemaster[STATCOUNTERS_READ_RSP]);
            fprintf(fp, "tagcachemaster_read_rsp_flit: \t%lu\n",b->tagcachemaster[STATCOUNTERS_READ_RSP_FLIT]);
            fprintf(fp, "tagcachemaster_write_rsp:     \t%lu\n",b->tagcachemaster[STATCOUNTERS_WRITE_RSP]);
            fprintf(fp, "\n");
            fprintf(fp, "imprecise_setbounds:          \t%lu\n",b->imprecise_setbounds);
            fprintf(fp, "unrepresentable_caps:         \t%lu\n",b->unrepresentable_caps);
            fprintf(fp, "kernel emul unaligned access: \t%lu\n",b->kern_unaligned_access);
            fprintf(fp, "\n");
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
