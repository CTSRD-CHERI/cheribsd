#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>

extern size_t unw_context_size(void);
extern size_t unw_cursor_size(void);

int main() {
  // alignof unw_context_t/unw_cursor_t must be a multiple of sizeof(void*)
  static_assert(alignof(unw_context_t) >= alignof(void *),
                "incorrect alignment of unw_context_t");
  static_assert(alignof(unw_cursor_t) >= alignof(void *),
                "incorrect alignment of unw_cursor_t");

  if (unw_context_size() != sizeof(unw_context_t)) {
    fprintf(stderr,
            "sizeof(unw_context_t)=%zd, but library built with "
            "unw_context_size()=%zd\n",
            sizeof(unw_context_t), unw_context_size());
    abort();
  }
  if (unw_cursor_size() != sizeof(unw_cursor_t)) {
    fprintf(stderr,
            "sizeof(unw_cursor_t)=%zd, but library built with "
            "unw_cursor_size()=%zd\n",
            sizeof(unw_cursor_t), unw_cursor_size());
    abort();
  }
  fprintf(stderr, "Success!\n");
  return 0;
}
