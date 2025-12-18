.PATH: ${LIBC_SRCTOP}/stdlib/malloc

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/malloc/Symbol.map

MAN+=		malloc_revoke.3
MLINKS+=	malloc_revoke.3 malloc_is_revoking.3
MLINKS+=	malloc_revoke.3 malloc_revoke_enabled.3
MLINKS+=	malloc_revoke.3 malloc_revoke_quarantine_force_flush.3

.if ${MK_MALLOC_REVOCATION_SHIM} == no || !${MACHINE_ABI:Mpurecap}
MISRCS+=	malloc_quarantine.c
MISRCS+=	malloc_revoke.c
.endif

.if ${MK_MALLOC_REVOCATION_SHIM} == yes
.include "${LIBC_SRCTOP}/stdlib/malloc/mrs/Makefile.inc"
.endif

.include "${LIBC_SRCTOP}/stdlib/malloc/${OPT_LIBC_MALLOC}/Makefile.inc"
