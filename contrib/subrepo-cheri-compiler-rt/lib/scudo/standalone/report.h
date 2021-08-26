//===-- report.h ------------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef SCUDO_REPORT_H_
#define SCUDO_REPORT_H_

#include "internal_defs.h"

namespace scudo {

// Reports are *fatal* unless stated otherwise.

// Generic error.
void NORETURN reportError(const char *Message);

// Flags related errors.
void NORETURN reportInvalidFlag(const char *FlagType, const char *Value);

// Chunk header related errors.
void NORETURN reportHeaderCorruption(void *Ptr);
void NORETURN reportHeaderRace(void *Ptr);

// Sanity checks related error.
void NORETURN reportSanityCheckError(const char *Field);

// Combined allocator errors.
void NORETURN reportAlignmentTooBig(usize Alignment, uptr MaxAlignment);
void NORETURN reportAllocationSizeTooBig(uptr UserSize, uptr TotalSize,
                                         uptr MaxSize);
void NORETURN reportOutOfMemory(uptr RequestedSize);
enum class AllocatorAction : u8 {
  Recycling,
  Deallocating,
  Reallocating,
  Sizing,
};
void NORETURN reportInvalidChunkState(AllocatorAction Action, void *Ptr);
void NORETURN reportMisalignedPointer(AllocatorAction Action, void *Ptr);
void NORETURN reportDeallocTypeMismatch(AllocatorAction Action, void *Ptr,
                                        u8 TypeA, u8 TypeB);
void NORETURN reportDeleteSizeMismatch(void *Ptr, usize Size, uptr ExpectedSize);

// C wrappers errors.
void NORETURN reportAlignmentNotPowerOfTwo(usize Alignment);
void NORETURN reportInvalidPosixMemalignAlignment(usize Alignment);
void NORETURN reportCallocOverflow(uptr Count, usize Size);
void NORETURN reportPvallocOverflow(usize Size);
void NORETURN reportInvalidAlignedAllocAlignment(usize Size, usize Alignment);

} // namespace scudo

#endif // SCUDO_REPORT_H_
