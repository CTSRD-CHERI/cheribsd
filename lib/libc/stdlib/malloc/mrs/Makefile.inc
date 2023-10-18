.PATH: ${LIBC_SRCTOP}/stdlib/malloc/mrs

MISRCS+=	mrs.c

MAN+=	mrs.3
MLINKS+= \
	mrs.3 malloc.3 \
	mrs.3 calloc.3 \
	mrs.3 posix_memalign.3 \
	mrs.3 aligned_alloc.3 \
	mrs.3 realloc.3 \
	mrs.3 free.3 \
	mrs.3 malloc_revoke.3 \
	mrs.3 malloc_is_revoking.3

CFLAGS.mrs.c+=-Wno-error=gnu-folding-constant

# Allow quarantine to be enabled/disabled during program startup
CFLAGS.mrs.c+=	-DOPTIONAL_QUARANTINING

CFLAGS.mrs.c+=	-DMRS_REAL_PREFIX=${MRS_REAL_PREFIX}
