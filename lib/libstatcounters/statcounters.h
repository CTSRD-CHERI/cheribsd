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

#ifndef STATCOUNTERS_H
#define STATCOUNTERS_H

#include <stdint.h>
#include <stdio.h>

#include "statcounters_md.h"

// format flags
typedef enum {
	HUMAN_READABLE,
	CSV_HEADER,
	CSV_NOHEADER
} statcounters_fmt_flag_t;

__BEGIN_DECLS

// zero a statcounters_bank
int statcounters_zero(statcounters_bank_t * const cnt_bank);
// sample hardware counters in a statcounters_bank
int statcounters_sample(statcounters_bank_t * const cnt_bank);
// diff two statcounters_banks into a third one
int statcounters_diff(statcounters_bank_t * const bd,
    const statcounters_bank_t * const be, const statcounters_bank_t * const bs);
// dump a statcounters_bank in a file (csv or human readable)
int statcounters_dump(const statcounters_bank_t * const b);
int statcounters_dump_with_phase(const statcounters_bank_t * const b,
    const char *phase);
int statcounters_dump_with_args(const statcounters_bank_t * const b,
    const char *progname, const char *phase, const char *archname,
    FILE * const fp, const statcounters_fmt_flag_t fmt_flg);

const char *statcounters_get_next_name(const char *name);
int statcounters_id_from_name(const char *name);
uint64_t statcounters_sample_by_id(int id);

__END_DECLS

#endif
