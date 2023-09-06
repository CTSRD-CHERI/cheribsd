.PATH: ${LIBC_SRCTOP}/stdlib/malloc

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/malloc/Symbol.map

MAN+=		malloc_revoke.3

.if !${OPT_LIBC_MALLOC:Mdlmalloc} || !${MACHINE_ABI:Mpurecap}
MISRCS+=	malloc_revoke.c
.endif

.include "${LIBC_SRCTOP}/stdlib/malloc/${OPT_LIBC_MALLOC}/Makefile.inc"
