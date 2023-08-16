.PATH: ${LIBC_SRCTOP}/stdlib/malloc

MISRCS+=	malloc_revoke.c

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/malloc/Symbol.map

MAN+=		malloc_revoke.3

.include "${LIBC_SRCTOP}/stdlib/malloc/jemalloc/Makefile.inc"
