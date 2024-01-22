.PATH: ${LIBC_SRCTOP}/stdlib/malloc/snmalloc

MISRCS+=	malloc.cc

# Specify the locations in contrib for headers.
CXXFLAGS.malloc.cc+=	-I${SRCTOP}/contrib/subrepo-snmalloc/src/snmalloc

CXXSTD?=	c++20

# C++ dialect options.
CXXFLAGS+=	-fno-exceptions -fno-rtti

.if ${MACHINE_ARCH} == amd64
# The snmalloc x86 backend requires -mcx16 (part of x86-64-v2).
# XXX: unclear if this can be merged upstream.
CXXFLAGS.malloc.cc+=	-mcx16
.endif

# Require an explicit call from libthr to clean up thread-local state
CXXFLAGS.malloc.cc+=	-DSNMALLOC_USE_THREAD_CLEANUP
# Export compatibility implementations of the jemalloc non-standard and
# experimental APIs that are now part of the ABI contract for libc.
CXXFLAGS.malloc.cc+=	-DSNMALLOC_JEMALLOC3_EXPERIMENTAL
CXXFLAGS.malloc.cc+=	-DSNMALLOC_JEMALLOC_NONSTANDARD
# Use getentropy for random numbers.
CXXFLAGS.malloc.cc+=	-DSNMALLOC_PLATFORM_HAS_GETENTROPY
# Prefix all of these functions with double underscore:
CXXFLAGS.malloc.cc+=	-DSNMALLOC_STATIC_LIBRARY_PREFIX=__

.if ${MK_MALLOC_PRODUCTION} != "yes" || !defined(MALLOC_PRODUCTION)
CXXFLAGS.malloc.cc+=	-DSNMALLOC_CHECK_CLIENT
CXXFLAGS.malloc.cc+=	-DSNMALLOC_FAIL_FAST=false
.endif

# Don't emit frame pointers, the fast path for malloc is sufficiently small
# that this adds measurable overhead.
CXXFLAGS.malloc.cc+=	-fomit-frame-pointer

# Disable asserts.  There are enough of these that it hurts performance a lot
# and doesn't help if you're debugging anything other than malloc.
CXXFLAGS.malloc.cc+=	-DNDEBUG

# Don't export standard names when we're building with mrs support.  Its
# wrappers will provide this functionality.
.if ${MK_MALLOC_REVOCATION_SHIM} == yes
CXXFLAGS.malloc.cc+=	-DMALLOC_REVOCATION_SHIM
MRS_REAL_PREFIX=__
.endif

# snmalloc relies a lot on inlining.  If a new version breaks, uncomment these
# lines to make it easy to debug.
#CXXFLAGS.malloc.cc+=	-O0 -fno-inline
