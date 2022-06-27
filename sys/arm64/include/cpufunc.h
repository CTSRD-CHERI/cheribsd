/*-
 * Copyright (c) 2014 Andrew Turner
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#ifndef _MACHINE_CPUFUNC_H_
#define	_MACHINE_CPUFUNC_H_

static __inline void
breakpoint(void)
{

	__asm("brk #0");
}

#ifdef _KERNEL

#define	HAVE_INLINE_FFS

static __inline __pure2 int
ffs(int mask)
{

	return (__builtin_ffs(mask));
}

#define	HAVE_INLINE_FFSL

static __inline __pure2 int
ffsl(long mask)
{

	return (__builtin_ffsl(mask));
}

#define	HAVE_INLINE_FFSLL

static __inline __pure2 int
ffsll(long long mask)
{

	return (__builtin_ffsll(mask));
}

#define	HAVE_INLINE_FLS

static __inline __pure2 int
fls(int mask)
{

	return (mask == 0 ? 0 :
	    8 * sizeof(mask) - __builtin_clz((u_int)mask));
}

#define	HAVE_INLINE_FLSL

static __inline __pure2 int
flsl(long mask)
{

	return (mask == 0 ? 0 :
	    8 * sizeof(mask) - __builtin_clzl((u_long)mask));
}

#define	HAVE_INLINE_FLSLL

static __inline __pure2 int
flsll(long long mask)
{

	return (mask == 0 ? 0 :
	    8 * sizeof(mask) - __builtin_clzll((unsigned long long)mask));
}

#include <machine/armreg.h>

void pan_enable(void);

static __inline register_t
dbg_disable(void)
{
	uint32_t ret;

	__asm __volatile(
	    "mrs %x0, daif   \n"
	    "msr daifset, #(" __XSTRING(DAIF_D) ") \n"
	    : "=&r" (ret));

	return (ret);
}

static __inline void
dbg_enable(void)
{

	__asm __volatile("msr daifclr, #(" __XSTRING(DAIF_D) ")");
}

static __inline register_t
intr_disable(void)
{
	/* DAIF is a 32-bit register */
	uint32_t ret;

	__asm __volatile(
	    "mrs %x0, daif   \n"
	    "msr daifset, #(" __XSTRING(DAIF_INTR) ") \n"
	    : "=&r" (ret));

	return (ret);
}

static __inline void
intr_restore(register_t s)
{

	WRITE_SPECIALREG(daif, s);
}

static __inline void
intr_enable(void)
{

	__asm __volatile("msr daifclr, #(" __XSTRING(DAIF_INTR) ")");
}

static __inline void
serror_enable(void)
{

	__asm __volatile("msr daifclr, #(" __XSTRING(DAIF_A) ")");
}

static __inline register_t
get_midr(void)
{
	uint64_t midr;

	midr = READ_SPECIALREG(midr_el1);

	return (midr);
}

static __inline register_t
get_mpidr(void)
{
	uint64_t mpidr;

	mpidr = READ_SPECIALREG(mpidr_el1);

	return (mpidr);
}

static __inline void
clrex(void)
{

	/*
	 * Ensure compiler barrier, otherwise the monitor clear might
	 * occur too late for us ?
	 */
	__asm __volatile("clrex" : : : "memory");
}

static __inline void
set_ttbr0(uint64_t ttbr0)
{

	__asm __volatile(
	    "msr ttbr0_el1, %0 \n"
	    "isb               \n"
	    :
	    : "r" (ttbr0));
}

static __inline void
invalidate_icache(void)
{

	__asm __volatile(
	    "ic ialluis        \n"
	    "dsb ish           \n"
	    "isb               \n");
}

static __inline void
invalidate_local_icache(void)
{

	__asm __volatile(
	    "ic iallu          \n"
	    "dsb nsh           \n"
	    "isb               \n");
}

extern bool icache_aliasing;
extern bool icache_vmid;

extern int64_t dcache_line_size;
extern int64_t icache_line_size;
extern int64_t idcache_line_size;
extern int64_t dczva_line_size;

#define	cpu_nullop()			arm64_nullop()
#define	cpufunc_nullop()		arm64_nullop()

#define	cpu_tlb_flushID()		arm64_tlb_flushID()

#define	cpu_dcache_wbinv_range(a, s)	arm64_dcache_wbinv_range((a), (s))
#define	cpu_dcache_inv_range(a, s)	arm64_dcache_inv_range((a), (s))
#define	cpu_dcache_wb_range(a, s)	arm64_dcache_wb_range((a), (s))

extern void (*arm64_icache_sync_range)(vm_pointer_t, vm_size_t);

#define	cpu_icache_sync_range(a, s)	arm64_icache_sync_range((a), (s))
#define cpu_icache_sync_range_checked(a, s) arm64_icache_sync_range_checked((a), (s))

void arm64_nullop(void);
void arm64_tlb_flushID(void);
void arm64_dic_idc_icache_sync_range(vm_pointer_t, vm_size_t);
void arm64_aliasing_icache_sync_range(vm_pointer_t, vm_size_t);
int arm64_icache_sync_range_checked(vm_pointer_t, vm_size_t);
void arm64_dcache_wbinv_range(vm_pointer_t, vm_size_t);
void arm64_dcache_inv_range(vm_pointer_t, vm_size_t);
void arm64_dcache_wb_range(vm_pointer_t, vm_size_t);
bool arm64_get_writable_addr(vm_pointer_t, vm_pointer_t *);

#endif	/* _KERNEL */

#define CHERI_START_TRACE do {			\
	__asm__ __volatile__("hlt #0xe003");	\
} while (0)

#define CHERI_STOP_TRACE do {			\
	__asm__ __volatile__("hlt #0xe004");	\
} while (0)

#define CHERI_START_USER_TRACE do {		\
	__asm__ __volatile__("hlt #0xe005");	\
} while (0)

#define CHERI_STOP_USER_TRACE do {		\
	__asm__ __volatile__("hlt #0xe004");	\
} while (0)

#define	QEMU_SET_TRACE_BUFFERED_MODE	do {	\
	__asm__ __volatile__("hlt #0xe000");	\
} while(0)

#define	QEMU_CLEAR_TRACE_BUFFERED_MODE	do {	\
	__asm__ __volatile__("hlt #0xe001");	\
} while(0)

#define	QEMU_FLUSH_TRACE_BUFFER do {		\
	__asm__ __volatile__("hlt #0xe002");	\
} while(0)

/*
 * Update qemu notion of the current context
 * pid: current pid
 * tid: current thread id
 * cid: compartment id
 */
#define	QEMU_EVENT_CONTEXT_UPDATE(pid, tid, cid)        \
	__asm__ __volatile__(				\
		"mov x0, #0x1\n"			\
		"mov x1, #0x0\n"			\
		"mov x2, %0\n"				\
		"mov x3, %1\n"				\
		"mov x4, %2\n"				\
		"hlt #0xe006\n"				\
		:: "r" (pid), "r" (tid), "r" (cid)	\
		: "x0", "x1", "x2", "x3", "x4")
/*
 * Arbitrary marker event to emit to the trace.
 * 0x00 - 0x9fff reserved for kernel-level markers
 * 0xa000 - 0xffff reserved for benchmarks use
 */
#define	QEMU_EVENT_MARKER(trace_marker)		\
	__asm__ __volatile__(			\
	    "mov x0, #0x2\n"			\
	    "mov x1, %0\n"			\
	    "hlt #0xe006\n"			\
	    :: "r" (trace_marker)		\
	    : "x0", "x1")

#define	QEMU_TRACE_MARKER_INTR_ENTRY	0x10
#define	QEMU_TRACE_MARKER_INTR_RET	0x11
#define	QEMU_TRACE_MARKER_BENCHMARK_ITERATION	0xbeef

/*
 * QEMU tracing counter event.
 * This is an (hopefully) low overhead counter that only
 * requires a NOP to be incremented/decremented.
 */
#define	QEMU_EVENT_COUNTER_FLAGS(slot, inc)			\
	((((uint64_t)inc & 0x1) << 32) | (slot & 0xffff))
#ifdef __CHERI_PURE_CAPABILITY__
#define	QEMU_EVENT_COUNTER(name, slot, value, incremental)		\
	__asm__ __volatile__(						\
	    "mov x0, #0x4\n"						\
	    "mov c1, %0\n"						\
	    "mov x2, %1\n"						\
	    "mov x3, %2\n"						\
	    "hlt #0xe006\n"						\
	    :: "C" (name), "r" ((int64_t)value),			\
	     "r" (QEMU_EVENT_COUNTER_FLAGS(slot, incremental))		\
	    : "x0", "c1", "x2", "x3")
#else
#define	QEMU_EVENT_COUNTER(name, slot, value, incremental)	\
	__asm__ __volatile__(					\
	    "mov x0, #0x4\n"					\
	    "mov x1, %0\n"					\
	    "mov x2, %1\n"					\
	    "mov x3, %2\n"					\
	    "hlt #0xe006\n"					\
	    :: "r" (name), "r" ((int64_t)value),		\
	     "r" (QEMU_EVENT_COUNTER_FLAGS(slot, incremental))	\
	    : "x0", "x1", "x2", "x3")
#endif
#define	QEMU_EVENT_ABS_COUNTER(name, slot, value)	\
	QEMU_EVENT_COUNTER(name, slot, value, 0)
#define	QEMU_EVENT_INC_COUNTER(name, slot, value)	\
	QEMU_EVENT_COUNTER(name, slot, value, 1)
#endif	/* _MACHINE_CPUFUNC_H_ */
