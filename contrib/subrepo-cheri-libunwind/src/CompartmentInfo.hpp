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

#ifdef __CHERI_PURE_CAPABILITY__

extern "C" {

// Must mirror the layout in rtld_c18n_machdep.h
#ifdef _LIBUNWIND_TARGET_AARCH64
struct dl_c18n_compart_state {
  void *fp;
  void *pc;
  void *regs[10]; // c19 to c28
  void *sp;
};
#endif

#pragma weak dl_c18n_is_tramp
int dl_c18n_is_tramp(ptraddr_t pc, void *tf) {
  return 0;
};

#pragma weak dl_c18n_pop_trusted_stk
void *dl_c18n_pop_trusted_stk(struct dl_c18n_compart_state *, void *);
}

#endif // __CHERI_PURE_CAPABILITY__

namespace libunwind {

// A wrapper for RTLD APIs related to library-based compartmentalisation (c18n).
template <typename A, typename R>
struct CompartmentInfo {
  typedef typename A::pint_t pint_t;

  static int unwindIfAtBoundary(R &registers) {
#ifdef __CHERI_PURE_CAPABILITY__
#ifdef _LIBUNWIND_TARGET_AARCH64
    struct dl_c18n_compart_state state;
    pint_t pc = registers.getIP();
    pint_t tf = registers.getTrustedStack();

    if (!dl_c18n_is_tramp(pc, (void *)tf))
      return UNW_STEP_SUCCESS;

    CHERI_DBG("COMPARTMENT BOUNDARY %#p\n", (void *)pc);

    tf = (pint_t)dl_c18n_pop_trusted_stk(&state, (void *)tf);

    registers.setTrustedStack(tf);
    CHERI_DBG("C18N: SET TRUSTED STACK %#p\n", (void *)tf);

    registers.setFP((pint_t)state.fp);
    CHERI_DBG("C18N: SET FP %#p\n", state.fp);

    registers.setSP((pint_t)state.sp);
    CHERI_DBG("C18N: SET SP: %#p\n", state.sp);

    registers.setIP((pint_t)state.pc);
    CHERI_DBG("C18N: SET IP: %#p\n", state.pc);

    for (size_t i = 0; i < sizeof(state.regs) / sizeof(*state.regs); ++i) {
      registers.setCapabilityRegister(UNW_ARM64_C19 + i, (pint_t)state.regs[i]);
      CHERI_DBG("C18N: SET REGISTER: %lu (%s): %#p\n",
                UNW_ARM64_C19 + i,
                registers.getRegisterName(UNW_ARM64_C19 + i),
                state.regs[i]);
    }
#endif
#endif
    return UNW_STEP_SUCCESS;
  }
};
} // namespace libunwind
#endif // __COMPARTMENT_INFO_HPP__
