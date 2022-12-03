# $FreeBSD$

.PATH: ${ZFSTOP}/module/avl

PACKAGE=	runtime
LIB=	avl
# The assert macro needs `int aok` (which is in nvpair)
LIBADD=	nvpair spl
SRCS=	avl.c
WARNS?=	3
CFLAGS+= -DIN_BASE
CFLAGS+= -I${ZFSTOP}/include
CFLAGS+= -I${ZFSTOP}/lib/libspl/include/
CFLAGS+= -I${ZFSTOP}/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -include ${ZFSTOP}/include/os/freebsd/spl/sys/ccompile.h

.include <bsd.lib.mk>
