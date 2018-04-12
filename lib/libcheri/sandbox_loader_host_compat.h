/*-
 * Copyright (c) 2018 Alex Richardson
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
#pragma once

#ifdef __linux__
/* The Linux queue macros don't have FOREACH_SAFE */
#include <bsd/sys/queue.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mman.h>

#include <stdint.h>
// Use the same page size as CHERI MIPS:
#undef PAGE_SIZE
#define PAGE_SIZE 4096

#define TEST_LOADELF 1
#define ELF_LOADER_DEBUG 2
#define DEBUG 2

/* On MacOS __CONCAT is defined as x ## y, which won't expand macros */
#undef __CONCAT
#define        __CONCAT1(x,y)        x ## y
#define        __CONCAT(x,y)        __CONCAT1(x,y)
#define __capability

#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#define	rounddown2(x, y) ((x)&(~((y)-1)))          /* if y is power of two */

typedef unsigned long vaddr_t;
typedef unsigned long vm_offset_t;

#ifndef MAP_PREFAULT_READ
#ifdef MAP_POPULATE
#define MAP_PREFAULT_READ MAP_POPULATE
#else
#define MAP_PREFAULT_READ 0
#endif
#endif

#ifndef __unused
#define __unused __attribute__((unused))
#endif

