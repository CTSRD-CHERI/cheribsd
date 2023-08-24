.PATH: ${LIBC_SRCTOP}/stdlib/malloc

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/malloc/Symbol.map

MAN+=		malloc_revoke.3

.if ${MK_DLMALLOC} == "no" || !${MACHINE_ABI:Mpurecap}
MISRCS+=	malloc_revoke.c

.include "${LIBC_SRCTOP}/stdlib/malloc/jemalloc/Makefile.inc"
.else
.include "${LIBC_SRCTOP}/stdlib/malloc/dlmalloc/Makefile.inc"
.endif
