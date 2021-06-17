# $FreeBSD$

PACKAGE=lib${LIB}
LIB=	vmmapi
SRCS=	vmmapi.c
INCS=	vmmapi.h

.if ${MACHINE_CPUARCH} == "amd64"
SRCS+=	vmmapi_freebsd.c
.endif

LIBADD=	util

CFLAGS+= -I${.CURDIR}

.include <bsd.lib.mk>
