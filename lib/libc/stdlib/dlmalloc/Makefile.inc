# $FreeBSD$

.PATH: ${LIBC_SRCTOP}/stdlib/dlmalloc
.PATH: ${SRCTOP}/contrib/dlmalloc

DLMALLOCSRCS:= dlmalloc_nonreuse.c dlmalloc_libc_stubs.c

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/dlmalloc/Symbol.map

CFLAGS+=-I${SRCTOP}/contrib/dlmalloc

.if ${MACHINE_ABI:Mpurecap}
DLMALLOC_CFLAGS+=	-DCHERI_SET_BOUNDS -DSAFE_FREEBUF
DLMALLOC_CFLAGS+=	-DDCONSOLIDATE_ON_FREE=1
DLMALLOC_CFLAGS+=	-DZERO_MEMORY=1
DLMALLOC_CFLAGS+=	-DSUPPORT_UNMAP=1
.if ${MK_CHERI_CAPREVOKE} == "yes"
# We used to need to add libcheri_caprevoke.c as a source file, too,
# but that gets included now as part of the tls_malloc goo and doing
# so again here results in duplicate symbol definitions.
DLMALLOC_CFLAGS+=	-DCAPREVOKE -DDEFAULT_MAX_FREEBUFBYTES=8388608
.endif
CFLAGS.dlmalloc_nonreuse.c+=	${DLMALLOC_CFLAGS}
.endif

SRCS+=	${DLMALLOCSRCS}
