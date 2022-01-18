#include <libunwind.h>
#include <stdlib.h>
#include <stdio.h>

void backtrace(int lower_bound) {
  unw_context_t context;
  unw_getcontext(&context);

  unw_cursor_t cursor;
  unw_init_local(&cursor, &context);

  char buffer[1024];
  size_t offset = 0;

  int n = 0;
  while (1) {
    n++;
    if (unw_get_proc_name(&cursor, buffer, sizeof(buffer), &offset) == 0) {
      fprintf(stderr, "Frame %d: %s+%p\n", n, buffer, (void*)(intptr_t)offset);
    } else {
      fprintf(stderr, "Frame %d: Could not get name for cursor\n", n);
    }
    if (n > 100) {
      fprintf(stderr, "ERROR: Got %d frames, but expected at most 100\n", n);
      abort();
    }
    int error = unw_step(&cursor);
    if (error == 0) {
      fprintf(stderr, "Note: Reached final frame after %d steps\n", n);
      break;
    } else if (error < 0) {
      fprintf(stderr, "ERROR: Got error in unw_step: %d\n", error);
      abort();
    }
  };

  if (n < lower_bound) {
    fprintf(stderr, "ERROR: Got %d frames, but expected at least %d\n", n, lower_bound);
    abort();
  }
}

__attribute__((noinline)) void test1(int i) {
  fprintf(stderr, "starting %s\n", __func__);
  backtrace(i);
  fprintf(stderr, "finished %s\n", __func__); // ensure return address is saved
}

__attribute__((noinline)) void test2(int i, int j) {
  fprintf(stderr, "starting %s\n", __func__);
  backtrace(i);
  test1(j);
  fprintf(stderr, "finished %s\n", __func__); // ensure return address is saved
}

__attribute__((noinline)) void test3(int i, int j, int k) {
  fprintf(stderr, "starting %s\n", __func__);
  backtrace(i);
  test2(j, k);
  fprintf(stderr, "finished %s\n", __func__); // ensure return address is saved
}

void test_no_info() {
  unw_context_t context;
  unw_getcontext(&context);

  unw_cursor_t cursor;
  unw_init_local(&cursor, &context);

  unw_proc_info_t info;
  int ret = unw_get_proc_info(&cursor, &info);
  if (ret != UNW_ESUCCESS)
    abort();

  // Set the IP to an address clearly outside any function.
  unw_set_reg(&cursor, UNW_REG_IP, (unw_word_t)0);

  ret = unw_get_proc_info(&cursor, &info);
  if (ret != UNW_ENOINFO)
    abort();
}

int main(int, char**) {
  test1(3);
  test2(3, 4);
  test3(3, 4, 5);
  test_no_info();
  fprintf(stderr, "Success!\n");
  return 0;
}
