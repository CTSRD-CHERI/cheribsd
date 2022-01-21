.PATH: ${LIBC_SRCTOP}/stdlib/malloc

MISRCS+=	malloc_revoke.c

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/malloc/Symbol.map

MAN+=		malloc_revoke.3

.if ${MK_SNMALLOC} == yes
.include "${LIBC_SRCTOP}/stdlib/malloc/snmalloc/Makefile.inc"
.else
.include "${LIBC_SRCTOP}/stdlib/malloc/jemalloc/Makefile.inc"
.endif
