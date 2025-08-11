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

#ifdef _LIBUNWIND_HAS_CHERI_LIB_C18N
#include <link.h>
#endif

namespace libunwind {

// A wrapper for RTLD APIs related to library-based compartmentalisation (c18n).
template <typename A, typename R>
struct CompartmentInfo {
  typedef typename A::pint_t pint_t;

  static int unwindIfAtBoundary(R &registers) {
#ifdef _LIBUNWIND_HAS_CHERI_LIB_C18N
    struct dl_c18n_compart_state state;
    pint_t pc = registers.getIP();
    pint_t tf = registers.getTrustedStack();

    if (!dl_c18n_is_trampoline(pc, (void *)tf))
      return UNW_STEP_SUCCESS;

    CHERI_DBG("COMPARTMENT BOUNDARY %#p\n", (void *)pc);

    tf = (pint_t)dl_c18n_pop_trusted_stack(&state, (void *)tf);

    registers.setTrustedStack(tf);
    CHERI_DBG("C18N: SET TRUSTED STACK %#p\n", (void *)tf);

#ifdef _LIBUNWIND_TARGET_AARCH64
    registers.setFP((pint_t)state.fp);
    CHERI_DBG("C18N: SET FP %#p\n", state.fp);
#endif

    registers.setSP((pint_t)state.sp);
    CHERI_DBG("C18N: SET SP: %#p\n", state.sp);

    registers.setIP((pint_t)state.pc);
    CHERI_DBG("C18N: SET IP: %#p\n", state.pc);

#ifdef _LIBUNWIND_TARGET_AARCH64
    static constexpr int callee_saved[] = {
      UNW_ARM64_C19, UNW_ARM64_C20, UNW_ARM64_C21, UNW_ARM64_C22, UNW_ARM64_C23,
      UNW_ARM64_C24, UNW_ARM64_C26, UNW_ARM64_C27, UNW_ARM64_C28, UNW_ARM64_C29
    };
#elif defined(_LIBUNWIND_TARGET_RISCV)
    static constexpr int callee_saved[] = {
      UNW_RISCV_X9, UNW_RISCV_X18, UNW_RISCV_X19, UNW_RISCV_X20, UNW_RISCV_X21,
      UNW_RISCV_X22, UNW_RISCV_X23, UNW_RISCV_X24, UNW_RISCV_X25, UNW_RISCV_X26,
      UNW_RISCV_X27, UNW_RISCV_X8
    };
#endif
    static_assert(sizeof(callee_saved) / sizeof(*callee_saved) ==
                  sizeof(state.regs) / sizeof(*state.regs),
                  "unexpected number of saved registers");

    for (size_t i = 0; i < sizeof(state.regs) / sizeof(*state.regs); ++i) {
      registers.setCapabilityRegister(callee_saved[i], (pint_t)state.regs[i]);
      CHERI_DBG("C18N: SET REGISTER: %d (%s): %#p\n",
                callee_saved[i],
                registers.getRegisterName(callee_saved[i]),
                state.regs[i]);
    }
#endif // _LIBUNWIND_HAS_CHERI_LIB_C18N
    return UNW_STEP_SUCCESS;
  }
};
} // namespace libunwind
#endif // __COMPARTMENT_INFO_HPP__
