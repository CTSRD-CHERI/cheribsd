#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cheri/cheric.h>
#include "dlmalloc_nonreuse.h"

#ifndef nitems
#define nitems(x)	(sizeof((x)) / sizeof((x)[0]))
#endif

const size_t sizes[] = {
	1,
	2,
	3, 4, 5,
	7, 8, 9,
	15, 16, 17,
	31, 32, 33,
	63, 64, 65,
	127, 128, 129,
	255, 256, 257,
	511, 512, 513,
	1023, 1024, 1025,
	2047, 2048, 2049,
	4095, 4096, 4097,
	1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1
};

#define bad_ptr(ptr, fmt, ...)	\
    _bad_ptr((ptr), __FILE__, __LINE__, (fmt), ##__VA_ARGS__)

void
_bad_ptr(void *ptr, const char *file, int line, const char *fmt, ...)
{
	va_list ap;

	printf("%s:%d: bad pointer %#p\n", file, line, ptr);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	if (fmt[strlen(fmt) - 1] != '\n')
		printf("\n");
	abort();
}

static void *
malloc_checked(size_t bytes)
{
	void *ptr;

	ptr = dlmalloc(bytes);
	if (bytes == 0 && ptr == NULL)
		return (ptr);
	if (!cheri_gettag(ptr))
		bad_ptr(ptr, "missing tag");
	if (cheri_getlen(ptr) < bytes)
		bad_ptr(ptr, "length is less than %zu", bytes);
#ifdef CHERI_SET_BOUNDS
	if (cheri_getoffset(ptr) != 0)
		bad_ptr(ptr, "pointer has non-zero offset");
#endif
	return (ptr);
}

static void *
calloc_checked(size_t number, size_t size)
{
	void *ptr;

	ptr = dlcalloc(number, size);
	if (number * size == 0 && ptr == NULL)
		return (ptr);
	if (!cheri_gettag(ptr))
		bad_ptr(ptr, "missing tag");
	if (cheri_getlen(ptr) < number * size)
		bad_ptr(ptr, "length is less than %zu", number * size);
#ifdef CHERI_SET_BOUNDS
	if (cheri_getoffset(ptr) != 0)
		bad_ptr(ptr, "pointer has non-zero offset");
#endif
	return (ptr);
}

static void *
realloc_checked(void *optr, size_t bytes)
{
	void *ptr;

	ptr = dlrealloc(optr, bytes);
	if (bytes == 0 && ptr == NULL)
		return (ptr);
	if (!cheri_gettag(ptr))
		bad_ptr(ptr, "missing tag");
	if (cheri_getlen(ptr) < bytes)
		bad_ptr(ptr, "length is less than %zu", bytes);
#ifdef CHERI_SET_BOUNDS
	if (cheri_getoffset(ptr) != 0)
		bad_ptr(ptr, "pointer has non-zero offset");
#endif
	return (ptr);
}

int
main(int argc, char **argv)
{
	void *ptrs[nitems(sizes)];
	int i;

	/* ----- malloc tests ----- */
	for (i = 0; i < nitems(sizes); i++)
		ptrs[i] = malloc_checked(sizes[i]);
#ifdef CAPREVOKE
	dlmalloc_revoke();
	for (i = 0; i < nitems(sizes); i++)
		if (cheri_getperm(ptrs[i]) == 0)
			bad_ptr(ptrs[i],
			    "ptrs[%d] is revoked before being freed", i);
#endif
	/* Free even pointers */
	for (i = 0; i < nitems(sizes); i += 2)
		dlfree(ptrs[i]);
#ifdef CAPREVOKE
	dlmalloc_revoke();
	/*
	 * Check that even pointers were revoked and odd ones were not,
	 * freeing odd ones.
	 */
	for (i = 0; i < nitems(sizes); i += 2)
		if (cheri_getperm(ptrs[i]) != 0)
			bad_ptr(ptrs[i], "ptrs[%d] was not revoked", i);
	for (i = 1; i < nitems(sizes); i += 2)
		if (cheri_getperm(ptrs[i]) == 0)
			bad_ptr(ptrs[i],
			    "ptrs[%d] is revoked before being freed", i);
	dlmalloc_revoke();
#endif
	/* Free odd pointers */
	for (i = 1; i < nitems(sizes); i += 2)
		dlfree(ptrs[i]);

	/* ----- calloc tests ----- */
	for (i = 0; i < nitems(sizes); i++)
		ptrs[i] = calloc_checked(1, sizes[i]);
#ifdef CAPREVOKE
	dlmalloc_revoke();
	for (i = 0; i < nitems(sizes); i++)
		if (cheri_getperm(ptrs[i]) == 0)
			bad_ptr(ptrs[i],
			    "ptrs[%d] is revoked before being freed", i);
#endif
	/* Free even pointers */
	for (i = 0; i < nitems(sizes); i += 2)
		dlfree(ptrs[i]);
#ifdef CAPREVOKE
	dlmalloc_revoke();
	/*
	 * Check that even pointers were revoked and odd ones were not,
	 * freeing odd ones.
	 */
	for (i = 0; i < nitems(sizes); i += 2)
		if (cheri_getperm(ptrs[i]) != 0)
			bad_ptr(ptrs[i], "ptrs[%d] was not revoked", i);
	for (i = 1; i < nitems(sizes); i += 2)
		if (cheri_getperm(ptrs[i]) == 0)
			bad_ptr(ptrs[i],
			    "ptrs[%d] is revoked before being freed", i);
	dlmalloc_revoke();
#endif
	/* Free odd pointers */
	for (i = 1; i < nitems(sizes); i += 2)
		dlfree(ptrs[i]);

	/* ----- realloc tests ----- */
	ptrs[0] = realloc_checked(NULL, sizes[0]);
	for (i = 1; i < nitems(sizes); i++)
		ptrs[i] = realloc_checked(ptrs[i - 1], sizes[i]);
	dlfree(ptrs[nitems(sizes) - 1]);
#ifdef CAPREVOKE
	dlmalloc_revoke();
	for (i = 0; i < nitems(sizes); i++)
		if (cheri_getperm(ptrs[i]) != 0)
			bad_ptr(ptrs[i], "ptrs[%d] was not revoked", i);
#endif

	return (0);
}
