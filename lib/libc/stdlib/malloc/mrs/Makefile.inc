.PATH: ${LIBC_SRCTOP}/stdlib/malloc/mrs

MISRCS+=	mrs.c

CFLAGS.mrs.c+=-Wno-error=gnu-folding-constant

# Allow quarantine to be enabled/disabled during program startup
CFLAGS.mrs.c+=	-DOPTIONAL_QUARANTINING

.if ${OPT_LIBC_MALLOC:Msnmalloc}
CFLAGS.mrs.c+=	-DMRS_REAL_PREFIX=${MRS_REAL_PREFIX}
.else
.error mrs: unsupported malloc (${LIBC_MALLOC})
.endif
