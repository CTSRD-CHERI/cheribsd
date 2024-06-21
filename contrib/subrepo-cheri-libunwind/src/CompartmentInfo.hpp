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

extern "C" {

struct trusted_frame;

// Must mirror the layout in rtld_c18n_machdep.h
#if defined(_LIBUNWIND_TARGET_AARCH64)
struct compart_state {
  void *fp;
  void *pc;
  void *regs[10]; // c19 to c28
  void *sp;
};
#else
# error "LIBUNWIND_CHERI_C18N_SUPPORT is not supported on this target"
#endif

#pragma weak c18n_is_enabled
bool c18n_is_enabled(void) {
  return false;
};

#pragma weak c18n_is_tramp
bool c18n_is_tramp(ptraddr_t, struct trusted_frame *);

#pragma weak c18n_pop_trusted_stk
struct trusted_frame *
c18n_pop_trusted_stk(struct compart_state *, struct trusted_frame *);
}

template <typename A, typename R>
struct CompartmentInfo {
  typedef typename A::pint_t pint_t;

  static bool isC18NEnabled() {
    return c18n_is_enabled();
  }

  static bool isC18NTramp(pint_t pc, pint_t tf) {
    return c18n_is_tramp(pc, (struct trusted_frame *)tf);
  }

  static pint_t fillC18NState(R &newRegisters, pint_t tf) {
    struct compart_state state;
    tf = (pint_t)c18n_pop_trusted_stk(&state, (struct trusted_frame *)tf);

    newRegisters.setTrustedStack(tf);
    CHERI_DBG("C18N: SET TRUSTED STACK %#p\n", (void *)tf);

    newRegisters.setFP((pint_t)state.fp);
    CHERI_DBG("C18N: SET FP %#p\n", state.fp);

    newRegisters.setSP((pint_t)state.sp);
    CHERI_DBG("C18N: SET SP: %#p\n", state.sp);

    for (size_t i = 0; i < sizeof(state.regs) / sizeof(*state.regs); ++i) {
      newRegisters.setCapabilityRegister(UNW_ARM64_C19 + i,
          (pint_t)state.regs[i]);
      CHERI_DBG("C18N: SET REGISTER: %lu (%s): %#p\n",
                UNW_ARM64_C19 + i,
                newRegisters.getRegisterName(UNW_ARM64_C19 + i),
                state.regs[i]);
    }

    return (pint_t)state.pc;
  }
};
} // namespace libunwind
#endif // __COMPARTMENT_INFO_HPP__
