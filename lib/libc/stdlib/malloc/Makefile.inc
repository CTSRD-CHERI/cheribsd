.PATH: ${LIBC_SRCTOP}/stdlib/malloc

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/malloc/Symbol.map

.if ${MK_MALLOC_REVOCATION_SHIM} == no || !${MACHINE_ABI:Mpurecap}
MAN+=		malloc_revoke.3

MISRCS+=	malloc_revoke.c
.endif

.if ${MK_MALLOC_REVOCATION_SHIM} == yes
.include "${LIBC_SRCTOP}/stdlib/malloc/mrs/Makefile.inc"
.endif

.include "${LIBC_SRCTOP}/stdlib/malloc/${OPT_LIBC_MALLOC}/Makefile.inc"
