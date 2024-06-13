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

namespace libunwind {
class _LIBUNWIND_HIDDEN CompartmentInfo {
public:
#if defined(__CHERI_PURE_CAPABILITY__) && defined(_LIBUNWIND_CHERI_C18N_SUPPORT)
  static CompartmentInfo sThisCompartmentInfo;
  // Per-architecture trusted stack frame layout.
#if defined(_LIBUNWIND_TARGET_AARCH64)
  static const uint32_t kNewSPOffset = 12 * sizeof(void *);
  static const uint32_t kNextOffset = 14 * sizeof(void *);
  static const uint32_t kCalleeSavedOffset = 2 * sizeof(void *);
  static const uint32_t kCalleeSavedCount = 10;
  static const uint32_t kReturnAddressOffset = 15 * sizeof(void *) + 8;
  static const uint32_t kPCOffset = sizeof(void *);
#endif // _LIBUNWIND_TARGET_AARCH64
#endif // __CHERI_PURE_CAPABILITY__ && _LIBUNWIND_CHERI_C18N_SUPPORT
};
} // namespace libunwind
#endif // __COMPARTMENT_INFO_HPP__
