// Check that we can unwind threads without asserting
// This was not the case on CheriBSD
// We need to explicitly link with -pthreads:
// ADDITIONAL_LINK_FLAGS: -pthreads -lpthread
#include <dlfcn.h>
#include <err.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unwind.h>

// Note: none of these functions are static so that dladdr() can return names
// for each function.
void thread_unwind_cleanup(_Unwind_Reason_Code code,
                                  struct _Unwind_Exception *e) {
  fprintf(stderr, "%s(%d, %p) should not be called!", __func__, code, e);
  abort();
}

_Unwind_Reason_Code thread_unwind_callback(int version, _Unwind_Action actions,
                                           uint64_t exc_class,
                                           struct _Unwind_Exception *exc_obj,
                                           struct _Unwind_Context *context,
                                           void *stop_parameter) {
  (void)version;
  (void)exc_class;
  (void)exc_obj;
  (void)stop_parameter;
  void *cfa = (void *)_Unwind_GetCFA(context);
  void *ip = (void *)_Unwind_GetIP(context);
  fprintf(stderr, "%s: actions=0x%x, cfa=%p, ip=%p\n", __func__, actions, cfa,
          ip);
  if (actions & _UA_END_OF_STACK) {
    return _URC_END_OF_STACK; // stop now
  }
  if (ip == nullptr) {
    fprintf(stderr, "ip == NULL, should have have set _UA_END_OF_STACK\n");
    abort();
  }
  Dl_info dlinfo;
  if (dladdr(ip, &dlinfo)) {
    fprintf(stderr, "%s: IP %p is %s in %s\n", __func__, ip,
            dlinfo.dli_sname ? dlinfo.dli_sname : "<unknown function>",
            dlinfo.dli_fname);
  } else {
    fprintf(stderr, "%s: %p is in unknown function\n", __func__, ip);
  }
  return (_URC_NO_REASON);
}

static struct _Unwind_Exception ex;

__attribute__((noinline))
void call_Unwind_ForcedUnwind() {
  fprintf(stderr, "thread started!\n");
  memset(&ex, 0, sizeof(ex));
  ex.exception_cleanup = thread_unwind_cleanup;
  _Unwind_ForcedUnwind(&ex, thread_unwind_callback, nullptr);
  fprintf(stderr, "_Unwind_ForcedUnwind returned\n");
}

__attribute__((noinline))
void *unwind_new_thread(void *) {
  fprintf(stderr, "testing _Unwind_ForcedUnwind in other thread\n");
  call_Unwind_ForcedUnwind();
  fprintf(stderr, "finished testing _Unwind_ForcedUnwind in other thread\n");
  return (void *)(uintptr_t)0x1234;
}


__attribute__((noinline))
void unwind_main_thread() {
  fprintf(stderr, "testing _Unwind_ForcedUnwind in main thread\n");
  call_Unwind_ForcedUnwind();
  fprintf(stderr, "finished testing _Unwind_ForcedUnwind in main thread\n");
}

int main() {
  // setenv("LIBUNWIND_PRINT_UNWINDING", "1", 1);
  // setenv("LIBUNWIND_PRINT_CHERI", "1", 1);
  // setenv("LIBUNWIND_PRINT_DWARF", "1", 1);
  // setenv("LIBUNWIND_PRINT_APIS", "1", 1);
  fprintf(stderr, "Spawning thread!\n");
  pthread_t thr;
  pthread_create(&thr, nullptr, &unwind_new_thread, nullptr);
  void *result = nullptr;
  int err = pthread_join(thr, &result);
  if (err != 0) {
    errx(EX_OSERR, "pthread_join=%s", strerror(err));
  }
  if ((uintptr_t)result != (uintptr_t)0x1234) {
    fprintf(stderr, "Incorrect return value: %p\n", result);
    abort();
  }

  unwind_main_thread();

  fprintf(stderr, "Success!\n");
  return (0);
}
