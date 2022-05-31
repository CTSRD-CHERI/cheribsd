// UNSUPPORTED: no-exceptions
// Tell lit to add -lc++abi/-lcxxrt/-lsupc++, etc. to the linker flags:
// Note: we also have to append -lc when linking with ld.bfd since -lsupc++ is added at the end of the command line.
// FIXME: if link_libcxxabi==-lsupc++ it should include -lc when linking with ld.bfd
// ADDITIONAL_COMPILE_FLAGS: -fexceptions -frtti
// ADDITIONAL_LINK_FLAGS: %{link_libcxxabi} -lc

#include <stdio.h>
#include <stdlib.h>

static int dtors_called = 0;

struct WithCleanup {
  WithCleanup(const char *func) : func(func) {
    fprintf(stderr, "Created object with destructor in %s!\n", func);
  }
  WithCleanup(const WithCleanup &other) : func(other.func) {
    fprintf(stderr, "struct WithCleanup(%s) copied!\n", func);
  }
  ~WithCleanup() {
    fprintf(stderr, "Calling destructor in %s!\n", func);
    dtors_called++;
  }

private:
  const char *func;
};

struct SomeException {
  SomeException(const char *message) : message(message) {}
  const char *message;
};

__attribute__((noinline)) int raise_exception(bool raise) {
  if (raise) {
    fprintf(stderr, "About to throw an exception...\n");
    throw SomeException("Exception occurred.");
  } else {
    fprintf(stderr, "Not throwing yet...\n");
  }
  return 0;
};

__attribute__((noinline)) void test_function() {
  fprintf(stderr, "%s: enter\n", __func__);
  raise_exception(false);
  WithCleanup object(__func__);
  raise_exception(true);
  fprintf(stderr, "ERROR: returned from raise_exception!\n");
  abort();
}

int main() {
  try {
    WithCleanup object(__func__);
    fprintf(stderr, "About to call test_function!\n");
    test_function();
    fprintf(stderr, "ERROR: returned from test_function!\n");
    abort();
  } catch (const SomeException &s) {
    fprintf(stderr, "%s: caught exception with message: %s\n", __func__,
            s.message);
  }
  if (dtors_called != 2) {
    fprintf(stderr, "Expected 2 destructors to be called but got %d\n",
            dtors_called);
    abort();
  }
  fprintf(stderr, "Success!\n");
  return (0);
}
