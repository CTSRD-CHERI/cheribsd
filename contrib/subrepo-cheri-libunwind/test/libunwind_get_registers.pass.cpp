#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>

#define fatal(...)                                                             \
  do {                                                                         \
    fprintf(stderr, __VA_ARGS__);                                              \
    abort();                                                                   \
  } while (0)

#ifdef __CHERI_PURE_CAPABILITY__
#define PRINT_PTR "%#p"
#else
#define PRINT_PTR "%p"
#endif

static void check_reg(unw_cursor_t *cursor, const char *name,
                      unw_regnum_t regnum, uintptr_t expected) {
  unw_word_t value;
  int err = unw_get_reg(cursor, regnum, &value);
  if (err != UNW_ESUCCESS) {
    fatal("Failed to get register %s: erro code %d\n", name, err);
  }
  if (value != expected) {
    fatal("Got wrong value for register %s: " PRINT_PTR " != " PRINT_PTR "\n",
          name, (void *)(uintptr_t)value, (void *)(uintptr_t)expected);
  }
  fprintf(stderr, "Register %s has expected value " PRINT_PTR "\n", name,
          (void *)(uintptr_t)expected);
}

#define CHECK_REG(num, expected) check_reg(cursor, #num, num, expected)

int main() {
  unw_context_t context;
  unw_cursor_t cursor;

  // Call unw_getcontext() once to avoid registers being clobbered by lazy
  // binding resolvers in RTLD.
  int ret = unw_getcontext(&context);
  if (ret != UNW_ESUCCESS)
    fatal("unw_getcontext failed with error code %d", ret);

#ifdef __mips__
  // Fetch the values of hi + lo since they will certainly not be clobbered
  // between the asm volatile and the call to unw_init_local()
  size_t expected_hi = 0x12345678;
  size_t expected_lo = 0x87654321;
  auto check_reg_values = [=](unw_context_t *context, unw_cursor_t *cursor) {
    CHECK_REG(UNW_MIPS_LO, expected_lo);
    CHECK_REG(UNW_MIPS_HI, expected_hi);
    // The address of context should have been captured as the argument passed
    // to unw_getcontext (in $c3/$a0):
#ifdef __CHERI_PURE_CAPABILITY__
    CHECK_REG(UNW_MIPS_C3, (uintptr_t)context);
#else
    CHECK_REG(UNW_MIPS_R4, (uintptr_t)context);
#endif
#ifdef __CHERI_CAPABILITY_TABLE__
    CHECK_REG(UNW_MIPS_DDC, (uintptr_t)NULL);
#endif
  };
  // Setup some registers that we can compare to the values stored in the
  // unw_cursor
#define ASM_SETUP_CONTEXT()                                                    \
  __asm__ volatile("mthi %[hi_value]\n\t"                                      \
                   "mtlo %[lo_value]"                                          \
                   : /* no outputs */                                          \
                   : [ hi_value ] "r"(expected_hi),                            \
                     [ lo_value ] "r"(expected_lo) /* inputs */                \
                   : "lo", "hi" /* clobbers */)
#elif defined(__riscv)
  size_t expected_s10 = 0x12345678;
  size_t expected_s11 = 0x87654321;
  auto check_reg_values = [=](unw_context_t *context, unw_cursor_t *cursor) {
    CHECK_REG(UNW_RISCV_X26, expected_s10);
    CHECK_REG(UNW_RISCV_X27, expected_s11);
    // The address of context should have been captured as the argument passed
    // to unw_getcontext (in a0/x10):
    CHECK_REG(UNW_RISCV_X10, (uintptr_t)context);
  };
#define ASM_SETUP_CONTEXT()                                                    \
  __asm__ volatile("mv s10, %0\n\t"                                            \
                   "mv s11, %1"                                                \
                   :                                                           \
                   : "r"(expected_s10), "r"(expected_s11)                      \
                   : "s10", "s11")
#elif defined(__x86_64__)
  // Check the value of r14 since they will almost certainly not be
  // clobbered between the asm volatile and the call to unw_init_local()
  size_t expected_r14 = 0x87654321;
  auto check_reg_values = [=](unw_context_t *context, unw_cursor_t *cursor) {
    (void)context;
    CHECK_REG(UNW_X86_64_R14, expected_r14);
  };
  // Setup some registers that we can compare to the values stored in the
  // unw_cursor
#define ASM_SETUP_CONTEXT()                                                    \
  __asm__ volatile("movq %[r14_value], %%r14\n\t"                              \
                   :                               /* no outputs */            \
                   : [r14_value] "X"(expected_r14) /* inputs */                \
                   : "r14" /* clobbers */)
#else
#warning "Test not implemented for this architecture"
  auto check_reg_values = [](unw_context_t *context, unw_cursor_t *cursor) {
    fprintf(stderr, "No checks defined for current architecture!\n");
  };
#define ASM_SETUP_CONTEXT() (void)0
#endif
  fprintf(stderr, "Setting up register values for unw_getcontext()\n");
  ASM_SETUP_CONTEXT();
  // This line should immediately follow the inline assembly to ensure that
  // the compiler doesn't insert additional register moves
  ret = unw_getcontext(&context);
  if (ret != UNW_ESUCCESS)
    fatal("unw_getcontext failed with error code %d", ret);
  ret = unw_init_local(&cursor, &context);
  if (ret != UNW_ESUCCESS)
    fatal("unw_init_local failed with error code %d", ret);
  check_reg_values(&context, &cursor);
  fprintf(stderr, "Success!\n");
  return 0;
}
