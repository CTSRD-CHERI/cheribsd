.PATH: ${LIBC_SRCTOP}/stdlib/malloc/mrs

MISRCS+=	mrs.c

CFLAGS.mrs.c+=-Wno-error=gnu-folding-constant

# Prefer load-side revocation
CFLAGS.mrs.c+=	-DLOAD_SIDE_REVOCATION

.if ${OPT_LIBC_MALLOC:Msnmalloc}
CFLAGS.mrs.c+=	-DMRS_REAL_PREFIX=${MRS_REAL_PREFIX}
.else
.error mrs: unsupported malloc (${LIBC_MALLOC})
.endif
