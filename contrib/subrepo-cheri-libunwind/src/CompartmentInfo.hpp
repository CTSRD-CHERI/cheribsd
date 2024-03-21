//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//
// Abstracts unwind information when used with a compartmentalizing runtime
// linker.
//
//===----------------------------------------------------------------------===//

#ifndef __COMPARTMENT_INFO_HPP__
#define __COMPARTMENT_INFO_HPP__

#include "AddressSpace.hpp"

namespace libunwind {
class _LIBUNWIND_HIDDEN CompartmentInfo {
public:
  static CompartmentInfo sThisCompartmentInfo;
#if defined(__CHERI_PURE_CAPABILITY__)
  static const uintcap_t kInvalidRCSP = (uintcap_t)0;
  // Per-architecture trusted stack frame layout.
#if defined(_LIBUNWIND_TARGET_AARCH64)
  static const uint32_t kNewSPOffset = 48;
  static const uint32_t kNextOffset = 32;
  static const uint32_t kFPOffset = 0;
  static const uint32_t kCalleeSavedOffset = 80;
  static const uint32_t kCalleeSavedCount = 10;
  static const uint32_t kCalleeSavedSize = 16;
  static const uint32_t kReturnAddressOffset = 40;
  static const uint32_t kPCOffset = 16;
  // kCalleeSavedCount - 1 because kCalleeSavedOffset is the first one.
  static const uint32_t kTrustedFrameSize =
      kCalleeSavedOffset + (kCalleeSavedCount - 1) * kCalleeSavedSize;
#endif // _LIBUNWIND_TARGET_AARCH64
#endif // __CHERI_PURE_CAPABILITY__
};
} // namespace libunwind
#endif // __COMPARTMENT_INFO_HPP__
