// UNSUPPORTED: no-exceptions
// Tell lit to add -lc++abi/-lcxxrt/-lsupc++, etc. to the linker flags:
// Note: we also have to append -lc when linking with ld.bfd since -lsupc++ is added at the end of the command line.
// FIXME: if link_libcxxabi==-lsupc++ it should include -lc when linking with ld.bfd
// ADDITIONAL_COMPILE_FLAGS: -fexceptions -frtti
// ADDITIONAL_LINK_FLAGS: %{link_libcxxabi} -lc

#include <stdio.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unwind.h>

struct Foo {
	Foo(int v, const char *s) : value(v), msg(s) {}
	int value;
	const char *msg;
};

static _Unwind_Reason_Code
print_frame(struct _Unwind_Context *ctx, void *arg)
{
	int *count = (int *)arg;

	printf("[%d]: %p\n", *count, (void *)_Unwind_GetIP(ctx));
	*count += 1;
	return (_URC_NO_REASON);
}

static void
some_function()
{
	int count = 0;

	_Unwind_Backtrace(print_frame, (void *)&count);
}

int
main()
{

	some_function();
	try {
		throw 4;
	} catch (int x) {
		printf("x = %d\n", x);
	}

	try {
		throw Foo(42, "oh well");
	} catch (Foo &f) {
		printf("value = %d, msg = \"%s\"\n", f.value, f.msg);
	}

	try {
		throw (double)3.14159;
	} catch (double d) {
		printf("d = %g\n", d);
	}

	fprintf(stderr, "Success!\n");

	return (0);
}
