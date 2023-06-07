//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "assembly.h"
#include "__libunwind_config.h"

    .text

#if !defined(__USING_SJLJ_EXCEPTIONS__)

#if defined(__i386__)

#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#   +                       +
#   +-----------------------+
#   + thread_state pointer  +
#   +-----------------------+
#   + return address        +
#   +-----------------------+   <-- SP
#   +                       +
#
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)

  _LIBUNWIND_CET_ENDBR
  push  %eax
  movl  8(%esp), %eax
  movl  %ebx,  4(%eax)
  movl  %ecx,  8(%eax)
  movl  %edx, 12(%eax)
  movl  %edi, 16(%eax)
  movl  %esi, 20(%eax)
  movl  %ebp, 24(%eax)
  movl  %esp, %edx
  addl  $8, %edx
  movl  %edx, 28(%eax)  # store what sp was at call site as esp
  # skip ss
  # skip eflags
  movl  4(%esp), %edx
  movl  %edx, 40(%eax)  # store return address as eip
  # skip cs
  # skip ds
  # skip es
  # skip fs
  # skip gs
  movl  (%esp), %edx
  movl  %edx, (%eax)  # store original eax
  popl  %eax
  xorl  %eax, %eax    # return UNW_ESUCCESS
  ret

#elif defined(__x86_64__)

#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#  thread_state pointer is in rdi
#
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
#if defined(_WIN64)
#define PTR %rcx
#define TMP %rdx
#else
#define PTR %rdi
#define TMP %rsi
#endif

  _LIBUNWIND_CET_ENDBR
  movq  %rax,   (PTR)
  movq  %rbx,  8(PTR)
  movq  %rcx, 16(PTR)
  movq  %rdx, 24(PTR)
  movq  %rdi, 32(PTR)
  movq  %rsi, 40(PTR)
  movq  %rbp, 48(PTR)
  movq  %rsp, 56(PTR)
  addq  $8,   56(PTR)
  movq  %r8,  64(PTR)
  movq  %r9,  72(PTR)
  movq  %r10, 80(PTR)
  movq  %r11, 88(PTR)
  movq  %r12, 96(PTR)
  movq  %r13,104(PTR)
  movq  %r14,112(PTR)
  movq  %r15,120(PTR)
  movq  (%rsp),TMP
  movq  TMP,128(PTR) # store return address as rip
  # skip rflags
  # skip cs
  # skip fs
  # skip gs

#if defined(_WIN64)
  movdqu %xmm0,176(PTR)
  movdqu %xmm1,192(PTR)
  movdqu %xmm2,208(PTR)
  movdqu %xmm3,224(PTR)
  movdqu %xmm4,240(PTR)
  movdqu %xmm5,256(PTR)
  movdqu %xmm6,272(PTR)
  movdqu %xmm7,288(PTR)
  movdqu %xmm8,304(PTR)
  movdqu %xmm9,320(PTR)
  movdqu %xmm10,336(PTR)
  movdqu %xmm11,352(PTR)
  movdqu %xmm12,368(PTR)
  movdqu %xmm13,384(PTR)
  movdqu %xmm14,400(PTR)
  movdqu %xmm15,416(PTR)
#endif
  xorl  %eax, %eax    # return UNW_ESUCCESS
  ret

#elif defined(__mips__) && defined(_ABIO32) && _MIPS_SIM == _ABIO32

#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#  thread_state pointer is in a0 ($4)
#
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
  .set push
  .set noat
  .set noreorder
  .set nomacro
  sw    $1, (4 * 1)($4)
  sw    $2, (4 * 2)($4)
  sw    $3, (4 * 3)($4)
  sw    $4, (4 * 4)($4)
  sw    $5, (4 * 5)($4)
  sw    $6, (4 * 6)($4)
  sw    $7, (4 * 7)($4)
  sw    $8, (4 * 8)($4)
  sw    $9, (4 * 9)($4)
  sw    $10, (4 * 10)($4)
  sw    $11, (4 * 11)($4)
  sw    $12, (4 * 12)($4)
  sw    $13, (4 * 13)($4)
  sw    $14, (4 * 14)($4)
  sw    $15, (4 * 15)($4)
  sw    $16, (4 * 16)($4)
  sw    $17, (4 * 17)($4)
  sw    $18, (4 * 18)($4)
  sw    $19, (4 * 19)($4)
  sw    $20, (4 * 20)($4)
  sw    $21, (4 * 21)($4)
  sw    $22, (4 * 22)($4)
  sw    $23, (4 * 23)($4)
  sw    $24, (4 * 24)($4)
  sw    $25, (4 * 25)($4)
  sw    $26, (4 * 26)($4)
  sw    $27, (4 * 27)($4)
  sw    $28, (4 * 28)($4)
  sw    $29, (4 * 29)($4)
  sw    $30, (4 * 30)($4)
  sw    $31, (4 * 31)($4)
  # Store return address to pc
  sw    $31, (4 * 32)($4)
  # hi and lo
  mfhi  $8
  sw    $8,  (4 * 33)($4)
  mflo  $8
  sw    $8,  (4 * 34)($4)
#ifdef __mips_hard_float
#if __mips_fpr != 64
  sdc1  $f0, (4 * 36 + 8 * 0)($4)
  sdc1  $f2, (4 * 36 + 8 * 2)($4)
  sdc1  $f4, (4 * 36 + 8 * 4)($4)
  sdc1  $f6, (4 * 36 + 8 * 6)($4)
  sdc1  $f8, (4 * 36 + 8 * 8)($4)
  sdc1  $f10, (4 * 36 + 8 * 10)($4)
  sdc1  $f12, (4 * 36 + 8 * 12)($4)
  sdc1  $f14, (4 * 36 + 8 * 14)($4)
  sdc1  $f16, (4 * 36 + 8 * 16)($4)
  sdc1  $f18, (4 * 36 + 8 * 18)($4)
  sdc1  $f20, (4 * 36 + 8 * 20)($4)
  sdc1  $f22, (4 * 36 + 8 * 22)($4)
  sdc1  $f24, (4 * 36 + 8 * 24)($4)
  sdc1  $f26, (4 * 36 + 8 * 26)($4)
  sdc1  $f28, (4 * 36 + 8 * 28)($4)
  sdc1  $f30, (4 * 36 + 8 * 30)($4)
#else
  sdc1  $f0, (4 * 36 + 8 * 0)($4)
  sdc1  $f1, (4 * 36 + 8 * 1)($4)
  sdc1  $f2, (4 * 36 + 8 * 2)($4)
  sdc1  $f3, (4 * 36 + 8 * 3)($4)
  sdc1  $f4, (4 * 36 + 8 * 4)($4)
  sdc1  $f5, (4 * 36 + 8 * 5)($4)
  sdc1  $f6, (4 * 36 + 8 * 6)($4)
  sdc1  $f7, (4 * 36 + 8 * 7)($4)
  sdc1  $f8, (4 * 36 + 8 * 8)($4)
  sdc1  $f9, (4 * 36 + 8 * 9)($4)
  sdc1  $f10, (4 * 36 + 8 * 10)($4)
  sdc1  $f11, (4 * 36 + 8 * 11)($4)
  sdc1  $f12, (4 * 36 + 8 * 12)($4)
  sdc1  $f13, (4 * 36 + 8 * 13)($4)
  sdc1  $f14, (4 * 36 + 8 * 14)($4)
  sdc1  $f15, (4 * 36 + 8 * 15)($4)
  sdc1  $f16, (4 * 36 + 8 * 16)($4)
  sdc1  $f17, (4 * 36 + 8 * 17)($4)
  sdc1  $f18, (4 * 36 + 8 * 18)($4)
  sdc1  $f19, (4 * 36 + 8 * 19)($4)
  sdc1  $f20, (4 * 36 + 8 * 20)($4)
  sdc1  $f21, (4 * 36 + 8 * 21)($4)
  sdc1  $f22, (4 * 36 + 8 * 22)($4)
  sdc1  $f23, (4 * 36 + 8 * 23)($4)
  sdc1  $f24, (4 * 36 + 8 * 24)($4)
  sdc1  $f25, (4 * 36 + 8 * 25)($4)
  sdc1  $f26, (4 * 36 + 8 * 26)($4)
  sdc1  $f27, (4 * 36 + 8 * 27)($4)
  sdc1  $f28, (4 * 36 + 8 * 28)($4)
  sdc1  $f29, (4 * 36 + 8 * 29)($4)
  sdc1  $f30, (4 * 36 + 8 * 30)($4)
  sdc1  $f31, (4 * 36 + 8 * 31)($4)
#endif
#endif
  jr	$31
  # return UNW_ESUCCESS
  or    $2, $0, $0
  .set pop
END_LIBUNWIND_FUNCTION(__unw_getcontext)

#elif defined(__mips__) && defined(__CHERI_PURE_CAPABILITY__)

#if !defined(__mips_soft_float)
#error "Only soft float supported"
#endif

.set noreorder
#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#  thread_state pointer is in $c3
#
# This is always called from ABI C code, so we only need to initialise the
# registers that are preserved across calls

DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
#define SAVE_GPR(x) csd $x, $zero, (8*x)($c3)
  SAVE_GPR(1) # $at
  SAVE_GPR(2) # $v0
  SAVE_GPR(3) # $v1
  SAVE_GPR(4) # $a0
  SAVE_GPR(5) # $a1
  SAVE_GPR(6) # $a2
  SAVE_GPR(7) # $a3
  SAVE_GPR(8) # $a4
  SAVE_GPR(9) # $a5
  SAVE_GPR(10) # $a6
  SAVE_GPR(11) # $a7
  SAVE_GPR(12) # $t0/t4
  SAVE_GPR(13) # $t1/t5
  SAVE_GPR(14) # $t2/t6
  SAVE_GPR(15) # $t3/t7
  SAVE_GPR(16) # $s0
  SAVE_GPR(17) # $s1
  SAVE_GPR(18) # $s2
  SAVE_GPR(19) # $s3
  SAVE_GPR(20) # $s4
  SAVE_GPR(21) # $s5
  SAVE_GPR(22) # $s6
  SAVE_GPR(23) # $s7
  SAVE_GPR(24) # $t8
  SAVE_GPR(25) # $t9
  SAVE_GPR(26) # $k0
  SAVE_GPR(27) # $k1
  SAVE_GPR(28) # $gp
  SAVE_GPR(29) # $sp
  SAVE_GPR(30) # $fp
  SAVE_GPR(31) # $ra

  # hi and lo
  mfhi	$t0
  csd	$t0, $zero, (8*64)($c3)
  mflo	$t0
  csd	$t0, $zero, (8*65)($c3)
  # TODO: floating point registers

#ifndef _LIBUNWIND_CAPREG_START
#error "_LIBUNWIND_CAPREG_START not defined"
#endif
#if ((_LIBUNWIND_CAPREG_START*64) % _MIPS_SZCAP) != 0
#error "unw_context capability register offset is not capability aligned!"
#endif
  /* Add the offset of the start of the capability register set to $at */
  daddiu $1, $zero, _LIBUNWIND_CAPREG_START*8
#define SAVE_CAP_REG(src, x) csc $c ## src, $1, (x * __SIZEOF_UINTCAP__)($c3)
#define SAVE_CAP(x) SAVE_CAP_REG(x, x)
  SAVE_CAP(1)
  SAVE_CAP(2)
  SAVE_CAP(3)
  SAVE_CAP(4)
  SAVE_CAP(5)
  SAVE_CAP(6)
  SAVE_CAP(7)
  SAVE_CAP(8)
  SAVE_CAP(9)
  SAVE_CAP(10)
  SAVE_CAP(11)
  SAVE_CAP(12)
  SAVE_CAP(13)
  SAVE_CAP(14)
  SAVE_CAP(15)
  SAVE_CAP(16)
  SAVE_CAP(17)
  SAVE_CAP(18)
  SAVE_CAP(19)
  SAVE_CAP(20)
  SAVE_CAP(21)
  SAVE_CAP(22)
  SAVE_CAP(23)
  SAVE_CAP(24)
  SAVE_CAP(25)
  SAVE_CAP(26)
  // store NULL for 27-31 since they are reserved for kernel use
  SAVE_CAP_REG(null, 27)
  SAVE_CAP_REG(null, 28)
  SAVE_CAP_REG(null, 29)
  SAVE_CAP_REG(null, 30)
  SAVE_CAP_REG(null, 31)

  // Use $c12 as a temp register in order to save $ddc since $c12 will hold
  // the cap for __unw_getcontext and it doesn't make sense to save it
  cgetdefault $c12
  SAVE_CAP_REG(12, 0)

  // return UNW_ESUCCESS
  daddiu $v0, $zero, 0
  # Store the return address where we expect the current PC
  daddiu $1, $1, 32*__SIZEOF_UINTCAP__
  cjr $c17
  csc $c17, $1, 0($c3)
END_LIBUNWIND_FUNCTION(__unw_getcontext)

#elif defined(__mips64)

#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#  thread_state pointer is in a0 ($4)
#
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
  .set push
  .set noat
  .set noreorder
  .set nomacro
  sd    $1, (8 * 1)($4)
  sd    $2, (8 * 2)($4)
  sd    $3, (8 * 3)($4)
  sd    $4, (8 * 4)($4)
  sd    $5, (8 * 5)($4)
  sd    $6, (8 * 6)($4)
  sd    $7, (8 * 7)($4)
  sd    $8, (8 * 8)($4)
  sd    $9, (8 * 9)($4)
  sd    $10, (8 * 10)($4)
  sd    $11, (8 * 11)($4)
  sd    $12, (8 * 12)($4)
  sd    $13, (8 * 13)($4)
  sd    $14, (8 * 14)($4)
  sd    $15, (8 * 15)($4)
  sd    $16, (8 * 16)($4)
  sd    $17, (8 * 17)($4)
  sd    $18, (8 * 18)($4)
  sd    $19, (8 * 19)($4)
  sd    $20, (8 * 20)($4)
  sd    $21, (8 * 21)($4)
  sd    $22, (8 * 22)($4)
  sd    $23, (8 * 23)($4)
  sd    $24, (8 * 24)($4)
  sd    $25, (8 * 25)($4)
  sd    $26, (8 * 26)($4)
  sd    $27, (8 * 27)($4)
  sd    $28, (8 * 28)($4)
  sd    $29, (8 * 29)($4)
  sd    $30, (8 * 30)($4)
  sd    $31, (8 * 31)($4)
  # Store return address to pc
  sd    $31, (8 * 32)($4)
  # hi and lo
  mfhi  $8
  sd    $8,  (8 * 33)($4)
  mflo  $8
  sd    $8,  (8 * 34)($4)
#ifdef __mips_hard_float
  sdc1  $f0, (8 * 35)($4)
  sdc1  $f1, (8 * 36)($4)
  sdc1  $f2, (8 * 37)($4)
  sdc1  $f3, (8 * 38)($4)
  sdc1  $f4, (8 * 39)($4)
  sdc1  $f5, (8 * 40)($4)
  sdc1  $f6, (8 * 41)($4)
  sdc1  $f7, (8 * 42)($4)
  sdc1  $f8, (8 * 43)($4)
  sdc1  $f9, (8 * 44)($4)
  sdc1  $f10, (8 * 45)($4)
  sdc1  $f11, (8 * 46)($4)
  sdc1  $f12, (8 * 47)($4)
  sdc1  $f13, (8 * 48)($4)
  sdc1  $f14, (8 * 49)($4)
  sdc1  $f15, (8 * 50)($4)
  sdc1  $f16, (8 * 51)($4)
  sdc1  $f17, (8 * 52)($4)
  sdc1  $f18, (8 * 53)($4)
  sdc1  $f19, (8 * 54)($4)
  sdc1  $f20, (8 * 55)($4)
  sdc1  $f21, (8 * 56)($4)
  sdc1  $f22, (8 * 57)($4)
  sdc1  $f23, (8 * 58)($4)
  sdc1  $f24, (8 * 59)($4)
  sdc1  $f25, (8 * 60)($4)
  sdc1  $f26, (8 * 61)($4)
  sdc1  $f27, (8 * 62)($4)
  sdc1  $f28, (8 * 63)($4)
  sdc1  $f29, (8 * 64)($4)
  sdc1  $f30, (8 * 65)($4)
  sdc1  $f31, (8 * 66)($4)
#endif
  jr	$31
  # return UNW_ESUCCESS
  or    $2, $0, $0
  .set pop
END_LIBUNWIND_FUNCTION(__unw_getcontext)

# elif defined(__mips__)

#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# Just trap for the time being.
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
  teq $0, $0
END_LIBUNWIND_FUNCTION(__unw_getcontext)

#elif defined(__powerpc64__)

//
// extern int __unw_getcontext(unw_context_t* thread_state)
//
// On entry:
//  thread_state pointer is in r3
//
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)

// store register (GPR)
#define PPC64_STR(n) \
  std   n, (8 * (n + 2))(3)

  // save GPRs
  PPC64_STR(0)
  mflr  0
  std   0, PPC64_OFFS_SRR0(3) // store lr as ssr0
  PPC64_STR(1)
  PPC64_STR(2)
  PPC64_STR(3)
  PPC64_STR(4)
  PPC64_STR(5)
  PPC64_STR(6)
  PPC64_STR(7)
  PPC64_STR(8)
  PPC64_STR(9)
  PPC64_STR(10)
  PPC64_STR(11)
  PPC64_STR(12)
  PPC64_STR(13)
  PPC64_STR(14)
  PPC64_STR(15)
  PPC64_STR(16)
  PPC64_STR(17)
  PPC64_STR(18)
  PPC64_STR(19)
  PPC64_STR(20)
  PPC64_STR(21)
  PPC64_STR(22)
  PPC64_STR(23)
  PPC64_STR(24)
  PPC64_STR(25)
  PPC64_STR(26)
  PPC64_STR(27)
  PPC64_STR(28)
  PPC64_STR(29)
  PPC64_STR(30)
  PPC64_STR(31)

  mfcr  0
  std   0,  PPC64_OFFS_CR(3)
  mfxer 0
  std   0,  PPC64_OFFS_XER(3)
  mflr  0
  std   0,  PPC64_OFFS_LR(3)
  mfctr 0
  std   0,  PPC64_OFFS_CTR(3)
  mfvrsave    0
  std   0,  PPC64_OFFS_VRSAVE(3)

#if defined(__VSX__)
  // save VS registers
  // (note that this also saves floating point registers and V registers,
  // because part of VS is mapped to these registers)

  addi  4, 3, PPC64_OFFS_FP

// store VS register
#define PPC64_STVS(n)      \
  stxvd2x n, 0, 4         ;\
  addi    4, 4, 16

  PPC64_STVS(0)
  PPC64_STVS(1)
  PPC64_STVS(2)
  PPC64_STVS(3)
  PPC64_STVS(4)
  PPC64_STVS(5)
  PPC64_STVS(6)
  PPC64_STVS(7)
  PPC64_STVS(8)
  PPC64_STVS(9)
  PPC64_STVS(10)
  PPC64_STVS(11)
  PPC64_STVS(12)
  PPC64_STVS(13)
  PPC64_STVS(14)
  PPC64_STVS(15)
  PPC64_STVS(16)
  PPC64_STVS(17)
  PPC64_STVS(18)
  PPC64_STVS(19)
  PPC64_STVS(20)
  PPC64_STVS(21)
  PPC64_STVS(22)
  PPC64_STVS(23)
  PPC64_STVS(24)
  PPC64_STVS(25)
  PPC64_STVS(26)
  PPC64_STVS(27)
  PPC64_STVS(28)
  PPC64_STVS(29)
  PPC64_STVS(30)
  PPC64_STVS(31)
  PPC64_STVS(32)
  PPC64_STVS(33)
  PPC64_STVS(34)
  PPC64_STVS(35)
  PPC64_STVS(36)
  PPC64_STVS(37)
  PPC64_STVS(38)
  PPC64_STVS(39)
  PPC64_STVS(40)
  PPC64_STVS(41)
  PPC64_STVS(42)
  PPC64_STVS(43)
  PPC64_STVS(44)
  PPC64_STVS(45)
  PPC64_STVS(46)
  PPC64_STVS(47)
  PPC64_STVS(48)
  PPC64_STVS(49)
  PPC64_STVS(50)
  PPC64_STVS(51)
  PPC64_STVS(52)
  PPC64_STVS(53)
  PPC64_STVS(54)
  PPC64_STVS(55)
  PPC64_STVS(56)
  PPC64_STVS(57)
  PPC64_STVS(58)
  PPC64_STVS(59)
  PPC64_STVS(60)
  PPC64_STVS(61)
  PPC64_STVS(62)
  PPC64_STVS(63)

#else

// store FP register
#define PPC64_STF(n) \
  stfd  n, (PPC64_OFFS_FP + n * 16)(3)

  // save float registers
  PPC64_STF(0)
  PPC64_STF(1)
  PPC64_STF(2)
  PPC64_STF(3)
  PPC64_STF(4)
  PPC64_STF(5)
  PPC64_STF(6)
  PPC64_STF(7)
  PPC64_STF(8)
  PPC64_STF(9)
  PPC64_STF(10)
  PPC64_STF(11)
  PPC64_STF(12)
  PPC64_STF(13)
  PPC64_STF(14)
  PPC64_STF(15)
  PPC64_STF(16)
  PPC64_STF(17)
  PPC64_STF(18)
  PPC64_STF(19)
  PPC64_STF(20)
  PPC64_STF(21)
  PPC64_STF(22)
  PPC64_STF(23)
  PPC64_STF(24)
  PPC64_STF(25)
  PPC64_STF(26)
  PPC64_STF(27)
  PPC64_STF(28)
  PPC64_STF(29)
  PPC64_STF(30)
  PPC64_STF(31)

#if defined(__ALTIVEC__)
  // save vector registers

  // Use 16-bytes below the stack pointer as an
  // aligned buffer to save each vector register.
  // Note that the stack pointer is always 16-byte aligned.
  subi  4, 1, 16

#define PPC64_STV_UNALIGNED(n)             \
  stvx  n, 0, 4                           ;\
  ld    5, 0(4)                           ;\
  std   5, (PPC64_OFFS_V + n * 16)(3)     ;\
  ld    5, 8(4)                           ;\
  std   5, (PPC64_OFFS_V + n * 16 + 8)(3)

  PPC64_STV_UNALIGNED(0)
  PPC64_STV_UNALIGNED(1)
  PPC64_STV_UNALIGNED(2)
  PPC64_STV_UNALIGNED(3)
  PPC64_STV_UNALIGNED(4)
  PPC64_STV_UNALIGNED(5)
  PPC64_STV_UNALIGNED(6)
  PPC64_STV_UNALIGNED(7)
  PPC64_STV_UNALIGNED(8)
  PPC64_STV_UNALIGNED(9)
  PPC64_STV_UNALIGNED(10)
  PPC64_STV_UNALIGNED(11)
  PPC64_STV_UNALIGNED(12)
  PPC64_STV_UNALIGNED(13)
  PPC64_STV_UNALIGNED(14)
  PPC64_STV_UNALIGNED(15)
  PPC64_STV_UNALIGNED(16)
  PPC64_STV_UNALIGNED(17)
  PPC64_STV_UNALIGNED(18)
  PPC64_STV_UNALIGNED(19)
  PPC64_STV_UNALIGNED(20)
  PPC64_STV_UNALIGNED(21)
  PPC64_STV_UNALIGNED(22)
  PPC64_STV_UNALIGNED(23)
  PPC64_STV_UNALIGNED(24)
  PPC64_STV_UNALIGNED(25)
  PPC64_STV_UNALIGNED(26)
  PPC64_STV_UNALIGNED(27)
  PPC64_STV_UNALIGNED(28)
  PPC64_STV_UNALIGNED(29)
  PPC64_STV_UNALIGNED(30)
  PPC64_STV_UNALIGNED(31)

#endif
#endif

  li    3,  0   // return UNW_ESUCCESS
  blr


#elif defined(__powerpc__)

//
// extern int unw_getcontext(unw_context_t* thread_state)
//
// On entry:
//  thread_state pointer is in r3
//
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
  stw     0,   8(3)
  mflr    0
  stw     0,   0(3) // store lr as ssr0
  stw     1,  12(3)
  stw     2,  16(3)
  stw     3,  20(3)
  stw     4,  24(3)
  stw     5,  28(3)
  stw     6,  32(3)
  stw     7,  36(3)
  stw     8,  40(3)
  stw     9,  44(3)
  stw     10, 48(3)
  stw     11, 52(3)
  stw     12, 56(3)
  stw     13, 60(3)
  stw     14, 64(3)
  stw     15, 68(3)
  stw     16, 72(3)
  stw     17, 76(3)
  stw     18, 80(3)
  stw     19, 84(3)
  stw     20, 88(3)
  stw     21, 92(3)
  stw     22, 96(3)
  stw     23,100(3)
  stw     24,104(3)
  stw     25,108(3)
  stw     26,112(3)
  stw     27,116(3)
  stw     28,120(3)
  stw     29,124(3)
  stw     30,128(3)
  stw     31,132(3)

  // save VRSave register
  mfspr   0, 256
  stw     0, 156(3)
  // save CR registers
  mfcr    0
  stw     0, 136(3)
  // save CTR register
  mfctr   0
  stw     0, 148(3)

#if !defined(__NO_FPRS__)
  // save float registers
  stfd    0, 160(3)
  stfd    1, 168(3)
  stfd    2, 176(3)
  stfd    3, 184(3)
  stfd    4, 192(3)
  stfd    5, 200(3)
  stfd    6, 208(3)
  stfd    7, 216(3)
  stfd    8, 224(3)
  stfd    9, 232(3)
  stfd    10,240(3)
  stfd    11,248(3)
  stfd    12,256(3)
  stfd    13,264(3)
  stfd    14,272(3)
  stfd    15,280(3)
  stfd    16,288(3)
  stfd    17,296(3)
  stfd    18,304(3)
  stfd    19,312(3)
  stfd    20,320(3)
  stfd    21,328(3)
  stfd    22,336(3)
  stfd    23,344(3)
  stfd    24,352(3)
  stfd    25,360(3)
  stfd    26,368(3)
  stfd    27,376(3)
  stfd    28,384(3)
  stfd    29,392(3)
  stfd    30,400(3)
  stfd    31,408(3)
#endif

#if defined(__ALTIVEC__)
  // save vector registers

  subi    4, 1, 16
  rlwinm  4, 4, 0, 0, 27  // mask low 4-bits
  // r4 is now a 16-byte aligned pointer into the red zone

#define SAVE_VECTOR_UNALIGNED(_vec, _offset) \
  stvx    _vec, 0, 4               SEPARATOR \
  lwz     5, 0(4)                  SEPARATOR \
  stw     5, _offset(3)            SEPARATOR \
  lwz     5, 4(4)                  SEPARATOR \
  stw     5, _offset+4(3)          SEPARATOR \
  lwz     5, 8(4)                  SEPARATOR \
  stw     5, _offset+8(3)          SEPARATOR \
  lwz     5, 12(4)                 SEPARATOR \
  stw     5, _offset+12(3)

  SAVE_VECTOR_UNALIGNED( 0, 424+0x000)
  SAVE_VECTOR_UNALIGNED( 1, 424+0x010)
  SAVE_VECTOR_UNALIGNED( 2, 424+0x020)
  SAVE_VECTOR_UNALIGNED( 3, 424+0x030)
  SAVE_VECTOR_UNALIGNED( 4, 424+0x040)
  SAVE_VECTOR_UNALIGNED( 5, 424+0x050)
  SAVE_VECTOR_UNALIGNED( 6, 424+0x060)
  SAVE_VECTOR_UNALIGNED( 7, 424+0x070)
  SAVE_VECTOR_UNALIGNED( 8, 424+0x080)
  SAVE_VECTOR_UNALIGNED( 9, 424+0x090)
  SAVE_VECTOR_UNALIGNED(10, 424+0x0A0)
  SAVE_VECTOR_UNALIGNED(11, 424+0x0B0)
  SAVE_VECTOR_UNALIGNED(12, 424+0x0C0)
  SAVE_VECTOR_UNALIGNED(13, 424+0x0D0)
  SAVE_VECTOR_UNALIGNED(14, 424+0x0E0)
  SAVE_VECTOR_UNALIGNED(15, 424+0x0F0)
  SAVE_VECTOR_UNALIGNED(16, 424+0x100)
  SAVE_VECTOR_UNALIGNED(17, 424+0x110)
  SAVE_VECTOR_UNALIGNED(18, 424+0x120)
  SAVE_VECTOR_UNALIGNED(19, 424+0x130)
  SAVE_VECTOR_UNALIGNED(20, 424+0x140)
  SAVE_VECTOR_UNALIGNED(21, 424+0x150)
  SAVE_VECTOR_UNALIGNED(22, 424+0x160)
  SAVE_VECTOR_UNALIGNED(23, 424+0x170)
  SAVE_VECTOR_UNALIGNED(24, 424+0x180)
  SAVE_VECTOR_UNALIGNED(25, 424+0x190)
  SAVE_VECTOR_UNALIGNED(26, 424+0x1A0)
  SAVE_VECTOR_UNALIGNED(27, 424+0x1B0)
  SAVE_VECTOR_UNALIGNED(28, 424+0x1C0)
  SAVE_VECTOR_UNALIGNED(29, 424+0x1D0)
  SAVE_VECTOR_UNALIGNED(30, 424+0x1E0)
  SAVE_VECTOR_UNALIGNED(31, 424+0x1F0)
#endif

  li      3, 0  // return UNW_ESUCCESS
  blr


#elif defined(__aarch64__)

//
// extern int __unw_getcontext(unw_context_t* thread_state)
//
// On entry:
//  thread_state pointer is in x0
//
  .p2align 2
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
#ifdef __CHERI_PURE_CAPABILITY__
  stp    c0, c1,  [c0, #0x000]
  stp    c2, c3,  [c0, #0x020]
  stp    c4, c5,  [c0, #0x040]
  stp    c6, c7,  [c0, #0x060]
  stp    c8, c9,  [c0, #0x080]
  stp    c10,c11, [c0, #0x0a0]
  stp    c12,c13, [c0, #0x0c0]
  stp    c14,c15, [c0, #0x0e0]
  stp    c16,c17, [c0, #0x100]
  stp    c18,c19, [c0, #0x120]
  stp    c20,c21, [c0, #0x140]
  stp    c22,c23, [c0, #0x160]
  stp    c24,c25, [c0, #0x180]
  stp    c26,c27, [c0, #0x1a0]
  stp    c28,c29, [c0, #0x1c0]
  str    c30,     [c0, #0x1e0]
  mov    c1,csp
  str    c1,      [c0, #0x1f0]
  str    c30,     [c0, #0x200]    // store return address as pcc
  // skip cpsr
  add    c0, c0, #0x220
  stp    d0, d1,  [c0, #0x000]
  stp    d2, d3,  [c0, #0x010]
  stp    d4, d5,  [c0, #0x020]
  stp    d6, d7,  [c0, #0x030]
  stp    d8, d9,  [c0, #0x040]
  stp    d10,d11, [c0, #0x050]
  stp    d12,d13, [c0, #0x060]
  stp    d14,d15, [c0, #0x070]
  stp    d16,d17, [c0, #0x080]
  stp    d18,d19, [c0, #0x090]
  stp    d20,d21, [c0, #0x0a0]
  stp    d22,d23, [c0, #0x0b0]
  stp    d24,d25, [c0, #0x0c0]
  stp    d26,d27, [c0, #0x0d0]
  stp    d28,d29, [c0, #0x0e0]
  str    d30,     [c0, #0x0f0]
  str    d31,     [c0, #0x0f8]
  mov    x0, #0                   // return UNW_ESUCCESS
  ret
#else
  stp    x0, x1,  [x0, #0x000]
  stp    x2, x3,  [x0, #0x010]
  stp    x4, x5,  [x0, #0x020]
  stp    x6, x7,  [x0, #0x030]
  stp    x8, x9,  [x0, #0x040]
  stp    x10,x11, [x0, #0x050]
  stp    x12,x13, [x0, #0x060]
  stp    x14,x15, [x0, #0x070]
  stp    x16,x17, [x0, #0x080]
  stp    x18,x19, [x0, #0x090]
  stp    x20,x21, [x0, #0x0A0]
  stp    x22,x23, [x0, #0x0B0]
  stp    x24,x25, [x0, #0x0C0]
  stp    x26,x27, [x0, #0x0D0]
  stp    x28,x29, [x0, #0x0E0]
  str    x30,     [x0, #0x0F0]
  mov    x1,sp
  str    x1,      [x0, #0x0F8]
  str    x30,     [x0, #0x100]    // store return address as pc
  // skip cpsr
  stp    d0, d1,  [x0, #0x110]
  stp    d2, d3,  [x0, #0x120]
  stp    d4, d5,  [x0, #0x130]
  stp    d6, d7,  [x0, #0x140]
  stp    d8, d9,  [x0, #0x150]
  stp    d10,d11, [x0, #0x160]
  stp    d12,d13, [x0, #0x170]
  stp    d14,d15, [x0, #0x180]
  stp    d16,d17, [x0, #0x190]
  stp    d18,d19, [x0, #0x1A0]
  stp    d20,d21, [x0, #0x1B0]
  stp    d22,d23, [x0, #0x1C0]
  stp    d24,d25, [x0, #0x1D0]
  stp    d26,d27, [x0, #0x1E0]
  stp    d28,d29, [x0, #0x1F0]
  str    d30,     [x0, #0x200]
  str    d31,     [x0, #0x208]
  mov    x0, #0                   // return UNW_ESUCCESS
  ret
#endif

#elif defined(__arm__) && !defined(__APPLE__)

#if !defined(__ARM_ARCH_ISA_ARM)
#if (__ARM_ARCH_ISA_THUMB == 2)
  .syntax unified
#endif
  .thumb
#endif

@
@ extern int __unw_getcontext(unw_context_t* thread_state)
@
@ On entry:
@  thread_state pointer is in r0
@ 
@ Per EHABI #4.7 this only saves the core integer registers.
@ EHABI #7.4.5 notes that in general all VRS registers should be restored
@ however this is very hard to do for VFP registers because it is unknown
@ to the library how many registers are implemented by the architecture.
@ Instead, VFP registers are demand saved by logic external to __unw_getcontext.
@
  .p2align 2
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
#if !defined(__ARM_ARCH_ISA_ARM) && __ARM_ARCH_ISA_THUMB == 1
  stm r0!, {r0-r7}
  mov r1, r8
  mov r2, r9
  mov r3, r10
  stm r0!, {r1-r3}
  mov r1, r11
  mov r2, sp
  mov r3, lr
  str r1, [r0, #0]   @ r11
  @ r12 does not need storing, it it the intra-procedure-call scratch register
  str r2, [r0, #8]   @ sp
  str r3, [r0, #12]  @ lr
  str r3, [r0, #16]  @ store return address as pc
  @ T1 does not have a non-cpsr-clobbering register-zeroing instruction.
  @ It is safe to use here though because we are about to return, and cpsr is
  @ not expected to be preserved.
  movs r0, #0        @ return UNW_ESUCCESS
#else
  @ 32bit thumb-2 restrictions for stm:
  @ . the sp (r13) cannot be in the list
  @ . the pc (r15) cannot be in the list in an STM instruction
  stm r0, {r0-r12}
  str sp, [r0, #52]
  str lr, [r0, #56]
  str lr, [r0, #60]  @ store return address as pc
  mov r0, #0         @ return UNW_ESUCCESS
#endif
  JMP(lr)

@
@ static void libunwind::Registers_arm::saveVFPWithFSTMD(unw_fpreg_t* values)
@
@ On entry:
@  values pointer is in r0
@
  .p2align 2
#if defined(__ELF__)
  .fpu vfpv3-d16
#endif
DEFINE_LIBUNWIND_FUNCTION(_ZN9libunwind13Registers_arm16saveVFPWithFSTMDEPv)
  vstmia r0, {d0-d15}
  JMP(lr)

@
@ static void libunwind::Registers_arm::saveVFPWithFSTMX(unw_fpreg_t* values)
@
@ On entry:
@  values pointer is in r0
@
  .p2align 2
#if defined(__ELF__)
  .fpu vfpv3-d16
#endif
DEFINE_LIBUNWIND_FUNCTION(_ZN9libunwind13Registers_arm16saveVFPWithFSTMXEPv)
  vstmia r0, {d0-d15} @ fstmiax is deprecated in ARMv7+ and now behaves like vstmia
  JMP(lr)

@
@ static void libunwind::Registers_arm::saveVFPv3(unw_fpreg_t* values)
@
@ On entry:
@  values pointer is in r0
@
  .p2align 2
#if defined(__ELF__)
  .fpu vfpv3
#endif
DEFINE_LIBUNWIND_FUNCTION(_ZN9libunwind13Registers_arm9saveVFPv3EPv)
  @ VFP and iwMMX instructions are only available when compiling with the flags
  @ that enable them. We do not want to do that in the library (because we do not
  @ want the compiler to generate instructions that access those) but this is
  @ only accessed if the personality routine needs these registers. Use of
  @ these registers implies they are, actually, available on the target, so
  @ it's ok to execute.
  @ So, generate the instructions using the corresponding coprocessor mnemonic.
  vstmia r0, {d16-d31}
  JMP(lr)

#if defined(_LIBUNWIND_ARM_WMMX)

@
@ static void libunwind::Registers_arm::saveiWMMX(unw_fpreg_t* values)
@
@ On entry:
@  values pointer is in r0
@
  .p2align 2
#if defined(__ELF__)
  .arch armv5te
#endif
DEFINE_LIBUNWIND_FUNCTION(_ZN9libunwind13Registers_arm9saveiWMMXEPv)
  stcl p1, cr0, [r0], #8  @ wstrd wR0, [r0], #8
  stcl p1, cr1, [r0], #8  @ wstrd wR1, [r0], #8
  stcl p1, cr2, [r0], #8  @ wstrd wR2, [r0], #8
  stcl p1, cr3, [r0], #8  @ wstrd wR3, [r0], #8
  stcl p1, cr4, [r0], #8  @ wstrd wR4, [r0], #8
  stcl p1, cr5, [r0], #8  @ wstrd wR5, [r0], #8
  stcl p1, cr6, [r0], #8  @ wstrd wR6, [r0], #8
  stcl p1, cr7, [r0], #8  @ wstrd wR7, [r0], #8
  stcl p1, cr8, [r0], #8  @ wstrd wR8, [r0], #8
  stcl p1, cr9, [r0], #8  @ wstrd wR9, [r0], #8
  stcl p1, cr10, [r0], #8  @ wstrd wR10, [r0], #8
  stcl p1, cr11, [r0], #8  @ wstrd wR11, [r0], #8
  stcl p1, cr12, [r0], #8  @ wstrd wR12, [r0], #8
  stcl p1, cr13, [r0], #8  @ wstrd wR13, [r0], #8
  stcl p1, cr14, [r0], #8  @ wstrd wR14, [r0], #8
  stcl p1, cr15, [r0], #8  @ wstrd wR15, [r0], #8
  JMP(lr)

@
@ static void libunwind::Registers_arm::saveiWMMXControl(unw_uint32_t* values)
@
@ On entry:
@  values pointer is in r0
@
  .p2align 2
#if defined(__ELF__)
  .arch armv5te
#endif
DEFINE_LIBUNWIND_FUNCTION(_ZN9libunwind13Registers_arm16saveiWMMXControlEPj)
  stc2 p1, cr8, [r0], #4  @ wstrw wCGR0, [r0], #4
  stc2 p1, cr9, [r0], #4  @ wstrw wCGR1, [r0], #4
  stc2 p1, cr10, [r0], #4  @ wstrw wCGR2, [r0], #4
  stc2 p1, cr11, [r0], #4  @ wstrw wCGR3, [r0], #4
  JMP(lr)

#endif

#elif defined(__or1k__)

#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#  thread_state pointer is in r3
#
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
  l.sw       0(r3), r0
  l.sw       4(r3), r1
  l.sw       8(r3), r2
  l.sw      12(r3), r3
  l.sw      16(r3), r4
  l.sw      20(r3), r5
  l.sw      24(r3), r6
  l.sw      28(r3), r7
  l.sw      32(r3), r8
  l.sw      36(r3), r9
  l.sw      40(r3), r10
  l.sw      44(r3), r11
  l.sw      48(r3), r12
  l.sw      52(r3), r13
  l.sw      56(r3), r14
  l.sw      60(r3), r15
  l.sw      64(r3), r16
  l.sw      68(r3), r17
  l.sw      72(r3), r18
  l.sw      76(r3), r19
  l.sw      80(r3), r20
  l.sw      84(r3), r21
  l.sw      88(r3), r22
  l.sw      92(r3), r23
  l.sw      96(r3), r24
  l.sw     100(r3), r25
  l.sw     104(r3), r26
  l.sw     108(r3), r27
  l.sw     112(r3), r28
  l.sw     116(r3), r29
  l.sw     120(r3), r30
  l.sw     124(r3), r31
  # store ra to pc
  l.sw     128(r3), r9
  # zero epcr
  l.sw     132(r3), r0

#elif defined(__hexagon__)
#
# extern int unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#  thread_state pointer is in r0
#
#define OFFSET(offset) (offset/4)
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
  memw(r0+#32) = r8
  memw(r0+#36) = r9
  memw(r0+#40) = r10
  memw(r0+#44) = r11

  memw(r0+#48) = r12
  memw(r0+#52) = r13
  memw(r0+#56) = r14
  memw(r0+#60) = r15

  memw(r0+#64) = r16
  memw(r0+#68) = r17
  memw(r0+#72) = r18
  memw(r0+#76) = r19

  memw(r0+#80) = r20
  memw(r0+#84) = r21
  memw(r0+#88) = r22
  memw(r0+#92) = r23

  memw(r0+#96) = r24
  memw(r0+#100) = r25
  memw(r0+#104) = r26
  memw(r0+#108) = r27

  memw(r0+#112) = r28
  memw(r0+#116) = r29
  memw(r0+#120) = r30
  memw(r0+#124) = r31
  r1 = c4   // Predicate register
  memw(r0+#128) = r1
  r1 = memw(r30)           // *FP == Saved FP
  r1 = r31
  memw(r0+#132) = r1

  jumpr r31

#elif defined(__sparc__)

#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#  thread_state pointer is in o0
#
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
  ta 3
  add %o7, 8, %o7
  std %g0, [%o0 +   0]
  std %g2, [%o0 +   8]
  std %g4, [%o0 +  16]
  std %g6, [%o0 +  24]
  std %o0, [%o0 +  32]
  std %o2, [%o0 +  40]
  std %o4, [%o0 +  48]
  std %o6, [%o0 +  56]
  std %l0, [%o0 +  64]
  std %l2, [%o0 +  72]
  std %l4, [%o0 +  80]
  std %l6, [%o0 +  88]
  std %i0, [%o0 +  96]
  std %i2, [%o0 + 104]
  std %i4, [%o0 + 112]
  std %i6, [%o0 + 120]
  jmp %o7
   clr %o0                   // return UNW_ESUCCESS

#elif defined(__riscv)

.macro save_fpr num
#ifdef __CHERI_PURE_CAPABILITY__
  cfsd   f\num, (__SIZEOF_CHERI_CAPABILITY__ * 32 + 8 * \num)(ca0)
#else
  FSTORE f\num, (8 * 32 + 8 * \num)(a0)
#endif
.endm

.macro save_gpr num
#ifdef __CHERI_PURE_CAPABILITY__
  csc   c\num, (__SIZEOF_CHERI_CAPABILITY__ * \num)(ca0)
#else
  ISTORE x\num, (8 * \num)(a0)
#endif
.endm

#
# extern int __unw_getcontext(unw_context_t* thread_state)
#
# On entry:
#  thread_state pointer is in a0
#
DEFINE_LIBUNWIND_FUNCTION(__unw_getcontext)
  // x0 is zero (index 0 is used for PC)
#ifdef __CHERI_PURE_CAPABILITY__
  csc   c1, (__SIZEOF_CHERI_CAPABILITY__ * 0)(ca0) // store ra as pc
#else
  ISTORE    x1, (8 * 0)(a0) // store ra as pc
#endif
  save_gpr 1
  save_gpr 2
  save_gpr 3
  save_gpr 4
  save_gpr 5
  save_gpr 6
  save_gpr 7
  save_gpr 8
  save_gpr 9
  save_gpr 10
  save_gpr 11
  save_gpr 12
  save_gpr 13
  save_gpr 14
  save_gpr 15
  save_gpr 16
  save_gpr 17
  save_gpr 18
  save_gpr 19
  save_gpr 20
  save_gpr 21
  save_gpr 22
  save_gpr 23
  save_gpr 24
  save_gpr 25
  save_gpr 26
  save_gpr 27
  save_gpr 28
  save_gpr 29
  save_gpr 30
  save_gpr 31

# if defined(__riscv_flen)
  save_fpr 0
  save_fpr 1
  save_fpr 2
  save_fpr 3
  save_fpr 4
  save_fpr 5
  save_fpr 6
  save_fpr 7
  save_fpr 8
  save_fpr 9
  save_fpr 10
  save_fpr 11
  save_fpr 12
  save_fpr 13
  save_fpr 14
  save_fpr 15
  save_fpr 16
  save_fpr 17
  save_fpr 18
  save_fpr 19
  save_fpr 20
  save_fpr 21
  save_fpr 22
  save_fpr 23
  save_fpr 24
  save_fpr 25
  save_fpr 26
  save_fpr 27
  save_fpr 28
  save_fpr 29
  save_fpr 30
  save_fpr 31
#endif

  li     a0, 0  // return UNW_ESUCCESS
#ifdef __CHERI_PURE_CAPABILITY__
  cret          // jump to cra
#else
  ret           // jump to ra
#endif
END_LIBUNWIND_FUNCTION(__unw_getcontext)

#endif

  WEAK_ALIAS(__unw_getcontext, unw_getcontext)

#endif /* !defined(__USING_SJLJ_EXCEPTIONS__) */

NO_EXEC_STACK_DIRECTIVE
