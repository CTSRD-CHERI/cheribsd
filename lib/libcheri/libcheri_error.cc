#include <sys/types.h>
#include <cheri/cheri.h>

#include "libcheri_sandbox.h"

libcheri::sandbox_invoke_failure::~sandbox_invoke_failure() throw() {}
const char *libcheri::sandbox_invoke_failure::what() const throw()
{
	return "libcheri sandbox invocation error.";
}

extern "C" void __cxa_libcheri_sandbox_invoke_failure(int e)
{
	libcheri::sandbox_invoke_failure ex(e);
	throw ex;
}
