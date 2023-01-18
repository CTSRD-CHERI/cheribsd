//===-- restore.S - restore up to 12 callee-save registers ----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Multiple entry points depending on number of registers to restore
//
//===----------------------------------------------------------------------===//

// All of the entry points are in the same section since we rely on many of
// them falling through into each other and don't want the linker to
// accidentally split them up, garbage collect, or reorder them.
//
// The entry points are grouped up into 2s for rv64 and 4s for rv32 since this
// is the minimum grouping which will maintain the required 16-byte stack
// alignment. Similarly, for CHERI, the entry points are grouped into 1s for
// rv64 and 2s for rv32.

  .text

#if __riscv_xlen == 32

# ifdef __CHERI_PURE_CAPABILITY__

  .globl     __riscv_restore_12
  .type      __riscv_restore_12,@function
__riscv_restore_12:
  clc        cs11, 8(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_11/10

  .globl     __riscv_restore_11
  .type      __riscv_restore_11,@function
  .globl     __riscv_restore_10
  .type      __riscv_restore_10,@function
__riscv_restore_11:
__riscv_restore_10:
  clc        cs10, 0(csp)
  clc        cs9,  8(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_9/8

  .globl     __riscv_restore_9
  .type      __riscv_restore_9,@function
  .globl     __riscv_restore_8
  .type      __riscv_restore_8,@function
__riscv_restore_9:
__riscv_restore_8:
  clc        cs8,  0(csp)
  clc        cs7,  8(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_7/6

  .globl     __riscv_restore_7
  .type      __riscv_restore_7,@function
  .globl     __riscv_restore_6
  .type      __riscv_restore_6,@function
__riscv_restore_7:
__riscv_restore_6:
  clc        cs6,  0(csp)
  clc        cs5,  8(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_5/4

  .globl     __riscv_restore_5
  .type      __riscv_restore_5,@function
  .globl     __riscv_restore_4
  .type      __riscv_restore_4,@function
__riscv_restore_5:
__riscv_restore_4:
  clc        cs4,  0(csp)
  clc        cs3,  8(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_3/2

  .globl     __riscv_restore_3
  .type      __riscv_restore_3,@function
  .globl     __riscv_restore_2
  .type      __riscv_restore_2,@function
__riscv_restore_3:
__riscv_restore_2:
  clc        cs2,  0(csp)
  clc        cs1,  8(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_1/0

  .globl     __riscv_restore_1
  .type      __riscv_restore_1,@function
  .globl     __riscv_restore_0
  .type      __riscv_restore_0,@function
__riscv_restore_1:
__riscv_restore_0:
  clc        cs0,  0(csp)
  clc        cra,  8(csp)
  cincoffset csp, csp, 16
  cret

# else

  .globl  __riscv_restore_12
  .type   __riscv_restore_12,@function
__riscv_restore_12:
  lw      s11, 12(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_11/10/9/8

  .globl  __riscv_restore_11
  .type   __riscv_restore_11,@function
  .globl  __riscv_restore_10
  .type   __riscv_restore_10,@function
  .globl  __riscv_restore_9
  .type   __riscv_restore_9,@function
  .globl  __riscv_restore_8
  .type   __riscv_restore_8,@function
__riscv_restore_11:
__riscv_restore_10:
__riscv_restore_9:
__riscv_restore_8:
  lw      s10, 0(sp)
  lw      s9,  4(sp)
  lw      s8,  8(sp)
  lw      s7,  12(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_7/6/5/4

  .globl  __riscv_restore_7
  .type   __riscv_restore_7,@function
  .globl  __riscv_restore_6
  .type   __riscv_restore_6,@function
  .globl  __riscv_restore_5
  .type   __riscv_restore_5,@function
  .globl  __riscv_restore_4
  .type   __riscv_restore_4,@function
__riscv_restore_7:
__riscv_restore_6:
__riscv_restore_5:
__riscv_restore_4:
  lw      s6,  0(sp)
  lw      s5,  4(sp)
  lw      s4,  8(sp)
  lw      s3,  12(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_3/2/1/0

  .globl  __riscv_restore_3
  .type   __riscv_restore_3,@function
  .globl  __riscv_restore_2
  .type   __riscv_restore_2,@function
  .globl  __riscv_restore_1
  .type   __riscv_restore_1,@function
  .globl  __riscv_restore_0
  .type   __riscv_restore_0,@function
__riscv_restore_3:
__riscv_restore_2:
__riscv_restore_1:
__riscv_restore_0:
  lw      s2,  0(sp)
  lw      s1,  4(sp)
  lw      s0,  8(sp)
  lw      ra,  12(sp)
  addi    sp, sp, 16
  ret

# endif

#elif __riscv_xlen == 64

# ifdef __CHERI_PURE_CAPABILITY__

  .globl     __riscv_restore_12
  .type      __riscv_restore_12,@function
__riscv_restore_12:
  clc        cs11, 0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_11

  .globl     __riscv_restore_11
  .type      __riscv_restore_11,@function
__riscv_restore_11:
  clc        cs10, 0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_10

  .globl     __riscv_restore_10
  .type      __riscv_restore_10,@function
__riscv_restore_10:
  clc        cs9,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_9

  .globl     __riscv_restore_9
  .type      __riscv_restore_9,@function
__riscv_restore_9:
  clc        cs8,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_8

  .globl     __riscv_restore_8
  .type      __riscv_restore_8,@function
__riscv_restore_8:
  clc        cs7,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_7

  .globl     __riscv_restore_7
  .type      __riscv_restore_7,@function
__riscv_restore_7:
  clc        cs6,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_6

  .globl     __riscv_restore_6
  .type      __riscv_restore_6,@function
__riscv_restore_6:
  clc        cs5,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_5

  .globl     __riscv_restore_5
  .type      __riscv_restore_5,@function
__riscv_restore_5:
  clc        cs4,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_4

  .globl     __riscv_restore_4
  .type      __riscv_restore_4,@function
__riscv_restore_4:
  clc        cs3,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_3

  .globl     __riscv_restore_3
  .type      __riscv_restore_3,@function
__riscv_restore_3:
  clc        cs2,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_2

  .globl     __riscv_restore_2
  .type      __riscv_restore_2,@function
__riscv_restore_2:
  clc        cs1,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_1

  .globl     __riscv_restore_1
  .type      __riscv_restore_1,@function
__riscv_restore_1:
  clc        cs0,  0(csp)
  cincoffset csp, csp, 16
  // fallthrough into __riscv_restore_0

  .globl     __riscv_restore_0
  .type      __riscv_restore_0,@function
__riscv_restore_0:
  clc        cra,  0(csp)
  cincoffset csp, csp, 16
  cret

# else

  .globl  __riscv_restore_12
  .type   __riscv_restore_12,@function
__riscv_restore_12:
  ld      s11, 8(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_11/10

  .globl  __riscv_restore_11
  .type   __riscv_restore_11,@function
  .globl  __riscv_restore_10
  .type   __riscv_restore_10,@function
__riscv_restore_11:
__riscv_restore_10:
  ld      s10, 0(sp)
  ld      s9,  8(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_9/8

  .globl  __riscv_restore_9
  .type   __riscv_restore_9,@function
  .globl  __riscv_restore_8
  .type   __riscv_restore_8,@function
__riscv_restore_9:
__riscv_restore_8:
  ld      s8,  0(sp)
  ld      s7,  8(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_7/6

  .globl  __riscv_restore_7
  .type   __riscv_restore_7,@function
  .globl  __riscv_restore_6
  .type   __riscv_restore_6,@function
__riscv_restore_7:
__riscv_restore_6:
  ld      s6,  0(sp)
  ld      s5,  8(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_5/4

  .globl  __riscv_restore_5
  .type   __riscv_restore_5,@function
  .globl  __riscv_restore_4
  .type   __riscv_restore_4,@function
__riscv_restore_5:
__riscv_restore_4:
  ld      s4,  0(sp)
  ld      s3,  8(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_3/2

  .globl  __riscv_restore_3
  .type   __riscv_restore_3,@function
  .globl  __riscv_restore_2
  .type   __riscv_restore_2,@function
__riscv_restore_3:
__riscv_restore_2:
  ld      s2,  0(sp)
  ld      s1,  8(sp)
  addi    sp, sp, 16
  // fallthrough into __riscv_restore_1/0

  .globl  __riscv_restore_1
  .type   __riscv_restore_1,@function
  .globl  __riscv_restore_0
  .type   __riscv_restore_0,@function
__riscv_restore_1:
__riscv_restore_0:
  ld      s0,  0(sp)
  ld      ra,  8(sp)
  addi    sp, sp, 16
  ret

# endif

#else
# error "xlen must be 32 or 64 for save-restore implementation
#endif
