//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
// Provides the constants and helpers for CHERI.
//===----------------------------------------------------------------------===//

#ifndef __UNWIND_CHERI_H__
#define __UNWIND_CHERI_H__

#ifdef __CHERI_PURE_CAPABILITY__
#define	_LIBUNWIND_CHERI_PERM_GLOBAL             (1 << 0) /* 0x00000001 */
#define	_LIBUNWIND_CHERI_PERM_EXECUTIVE          (1 << 1) /* 0x00000002 */
#define	_LIBUNWIND_CHERI_PERM_SW0                (1 << 2) /* 0x00000004 */
#define	_LIBUNWIND_CHERI_PERM_SW1                (1 << 3) /* 0x00000008 */
#define	_LIBUNWIND_CHERI_PERM_SW2                (1 << 4) /* 0x00000010 */
#define	_LIBUNWIND_CHERI_PERM_SW3                (1 << 5) /* 0x00000020 */
#define	_LIBUNWIND_CHERI_PERM_MUTABLE_LOAD       (1 << 6) /* 0x00000040 */
#define	_LIBUNWIND_CHERI_PERM_COMPARTMENT_ID     (1 << 7) /* 0x00000080 */
#define	_LIBUNWIND_CHERI_PERM_BRANCH_SEALED_PAIR (1 << 8) /* 0x00000100 */
#define	_LIBUNWIND_CHERI_PERM_INVOKE             CHERI_PERM_BRANCH_SEALED_PAIR
#define	_LIBUNWIND_CHERI_PERM_SYSTEM             (1 << 9) /* 0x00000200 */
#define	_LIBUNWIND_CHERI_PERM_SYSTEM_REGS        CHERI_PERM_SYSTEM
#define	_LIBUNWIND_CHERI_PERM_UNSEAL             (1 << 10) /* 0x00000400 */
#define	_LIBUNWIND_CHERI_PERM_SEAL               (1 << 11) /* 0x00000800 */
#define	_LIBUNWIND_CHERI_PERM_STORE_LOCAL_CAP    (1 << 12) /* 0x00001000 */
#define	_LIBUNWIND_CHERI_PERM_STORE_CAP          (1 << 13) /* 0x00002000 */
#define	_LIBUNWIND_CHERI_PERM_LOAD_CAP           (1 << 14) /* 0x00004000 */
#define	_LIBUNWIND_CHERI_PERM_EXECUTE            (1 << 15) /* 0x00008000 */
#define	_LIBUNWIND_CHERI_PERM_STORE              (1 << 16) /* 0x00010000 */
#define	_LIBUNWIND_CHERI_PERM_LOAD               (1 << 17) /* 0x00020000 */
#endif // __CHERI_PURE_CAPABILITY__

#endif // __UNWIND_CHERI_H__
