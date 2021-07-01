# $FreeBSD$

LIB=	helloworld
SRCS=	helloworld.c
INCS=	helloworld.h

LIBADD=	cheri
# libcheri is not built shared and is not PIC so creating a shared library
# linking against libcheri will not work correctly
NO_SHARED=	yes

INCSDIR=	${INCLUDEDIR}/cheri

SUBDIR=	compartment

.include <bsd.lib.mk>
