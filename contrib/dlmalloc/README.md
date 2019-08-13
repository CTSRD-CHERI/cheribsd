dlmalloc\_nonreuse
==================

This is a modified version of dlmalloc which delays the reuse of freed chunks
and consolidate just-freed chunks before eventually returning them back to the 
free pool. This allocator is intended to be used in conjunction with CHERI to
perform capability revocation.

Simply type make and link the final shared library "libdlmalloc\_nonreuse.so".
Do it like this:

`CC=clang LD=ld.lld DEBUG=0 gmake`

`DEBUG=1` enables debugging assertions which slows down the allocator quite a
bit. Only enable it in debugging.

Global compile-time variables
-----------------------------

The following compile-time #defines are the interesting bits to change or tweak.
They live in the header file.

```
USE_LOCKS
USE_SPIN_LOCKS
USE_RECURSIVE_LOCKS
HAVE_MMAP
MAX_RELEASE_CHECK_RATE
FREEBUF_MODE
DEFAULT_FREEBUF_PERCENT
DEFAULT_SWEEP_SIZE
SWEEP_STATS
MALLOC_UTRACE
```

`USE_LOCKS` should be 1 for thread safety.

`USE_SPIN_LOCKS` is 0 to use pthreads, but pthreads on many platforms depend on
malloc, so define it to 1 to use simple spin locks with C11 atomics.

`USE_RECURSIVE_LOCKS` should just be 0.

`MAX_RELEASE_RATE` indicates how many frees there are before traversing all
segments to release unused ones. The default value is reasonable enough.

`FREEBUF_MODE` enables the delaying of freed chunks, putting them inside a
free-buffer pool for consolidation and revocation before returning them to free
lists. Defining it to 0 turns it into just the original dlmalloc.

`DEFAULT_FREEBUF_PERCENT` is the ratio of the size of the free-buffer pool to
that of the normal heap, default being 25%.

`DEFAULT_SWEEP_SIZE` is for CHERI revocation, indicating how many chunks you
want to sweep per sweeping pass.

`SWEEP_STATS` registers the printing of statistics via `atexit()`. On some
platforms it has to be 0 because `atexit()` may depend on malloc.

`MALLOC_UTRACE` inject utrace entries for tracing. Define it to enable it. To
collect traces, run the application with `ktrace -tu cmd args...` which
generates a ktrace.out. Process it with `kdump -tu > trace.log` to parse the
binary format into human readable entries.
