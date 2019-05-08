#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


static int succeeded;
static int failed;
static bool verbose;

void log_test(bool predicate, const char *file, int line, const char *message)
{
	if (predicate)
	{
		if (verbose)
		{
			printf("Test passed: %s:%d: %s\n", file, line, message);
		}
		succeeded++;
		return;
	}
	failed++;
	printf("Test failed: %s:%d: %s\n", file, line, message);
}

static void log_totals(void)
{
	printf("\n%d tests, %d passed, %d failed\n", succeeded+failed, succeeded, failed);
}

static void __attribute__((constructor)) init(void)
{
	atexit(log_totals);
}

#ifndef LIBCXXRT_NO_EXCEPTIONS_NO_RTTI
void test_type_info(void);
void test_exceptions();
#endif
void test_guards(void);

int main(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "v")) != -1)
	{
		switch (ch)
		{
			case 'v':
				verbose = true;
			default: break;
		}
	}

#ifndef LIBCXXRT_NO_EXCEPTIONS_NO_RTTI
	test_type_info();
#endif
	test_guards();
#ifndef LIBCXXRT_NO_EXCEPTIONS_NO_RTTI
	test_exceptions();
#endif
	return 0;
}
