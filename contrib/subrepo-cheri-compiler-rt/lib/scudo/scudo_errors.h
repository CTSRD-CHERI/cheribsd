//===-- scudo_errors.h ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// Header for scudo_errors.cpp.
///
//===----------------------------------------------------------------------===//

#ifndef SCUDO_ERRORS_H_
#define SCUDO_ERRORS_H_

#include "sanitizer_common/sanitizer_internal_defs.h"

namespace __scudo {

void NORETURN reportCallocOverflow(uptr Count, usize Size);
void NORETURN reportPvallocOverflow(usize Size);
void NORETURN reportAllocationAlignmentTooBig(usize Alignment,
                                              uptr MaxAlignment);
void NORETURN reportAllocationAlignmentNotPowerOfTwo(usize Alignment);
void NORETURN reportInvalidPosixMemalignAlignment(usize Alignment);
void NORETURN reportInvalidAlignedAllocAlignment(usize Size, usize Alignment);
void NORETURN reportAllocationSizeTooBig(uptr UserSize, uptr TotalSize,
                                         uptr MaxSize);
void NORETURN reportRssLimitExceeded();
void NORETURN reportOutOfMemory(uptr RequestedSize);

}  // namespace __scudo

#endif  // SCUDO_ERRORS_H_
