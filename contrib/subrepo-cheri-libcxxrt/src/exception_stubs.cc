// These are the minimal stubs needed to be able to link libc++ with exceptions
// and rtti turned off with libcxxrt.

#include <stdlib.h>

namespace std {
	bool uncaught_exception() throw() { return false; }
	int uncaught_exceptions() throw() { return -1; }
	void terminate(void) { }
}

extern "C" void __cxa_rethrow_primary_exception(void* thrown_exception)
{
  abort();
}

extern "C" void *__cxa_current_primary_exception(void)
{
  abort();
}

extern "C" void __cxa_increment_exception_refcount(void* thrown_exception)
{
  abort();
}

extern "C" void __cxa_decrement_exception_refcount(void* thrown_exception)
{
  abort();
}
