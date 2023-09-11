.PATH: ${LIBC_SRCTOP}/stdlib/malloc

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/malloc/Symbol.map

MAN+=		malloc_revoke.3

.if (${MK_MALLOC_REVOCATION_SHIM} == no && !${OPT_LIBC_MALLOC:Mdlmalloc}) || !${MACHINE_ABI:Mpurecap}
MISRCS+=	malloc_revoke.c
.endif

.if ${MK_MALLOC_REVOCATION_SHIM} == yes
.include "${LIBC_SRCTOP}/stdlib/malloc/mrs/Makefile.inc"
.endif

.include "${LIBC_SRCTOP}/stdlib/malloc/${OPT_LIBC_MALLOC}/Makefile.inc"
