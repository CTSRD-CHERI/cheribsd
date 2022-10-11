#include <assert.h>
#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>

int main(int, char**) {
  unw_context_t context;
  int ret = unw_getcontext(&context);
  if (ret != UNW_ESUCCESS) {
    fprintf(stderr, "unw_getcontext() failed: %d!\n", ret);
    abort();
  }
  fprintf(stderr, "Success!\n");
  return 0;
}
