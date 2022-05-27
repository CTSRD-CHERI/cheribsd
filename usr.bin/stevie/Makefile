# $FreeBSD$

.include <src.opts.mk>

PROG=	stevie
SRCS=	stevie.c
MAN=

CFLAGS+=-Wno-error=deprecated-declarations
LIBADD=	pthread

WARNS?=	5

.include <bsd.prog.mk>
