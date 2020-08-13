# $FreeBSD$

.PATH: ${LIBC_SRCTOP}/stdlib/dlmalloc
.PATH: ${SRCTOP}/contrib/dlmalloc

DLMALLOCSRCS:= dlmalloc_nonreuse.c dlmalloc_libc_stubs.c

SYM_MAPS+=${LIBC_SRCTOP}/stdlib/dlmalloc/Symbol.map

CFLAGS+=-I${SRCTOP}/contrib/dlmalloc

.if ${MACHINE_ABI:Mpurecap}
DLMALLOC_CFLAGS+=	-DCHERI_SET_BOUNDS -DSAFE_FREEBUF
DLMALLOC_CFLAGS+=	-DDCONSOLIDATE_ON_FREE=1
DLMALLOC_CFLAGS+=	-DZERO_MEMORY=0
DLMALLOC_CFLAGS+=	-DSUPPORT_UNMAP=1
.if ${MK_CHERI_CAPREVOKE} == "yes"
.PATH: ${SRCTOP}/lib/libcheri_caprevoke
DLMALLOCSRCS+=		libcheri_caprevoke.c
DLMALLOC_CFLAGS+=	-DCAPREVOKE -DDEFAULT_MAX_FREEBUFBYTES=8388608
.endif
CFLAGS.dlmalloc_nonreuse.c+=	${DLMALLOC_CFLAGS}
.endif

SRCS+=	${DLMALLOCSRCS}
