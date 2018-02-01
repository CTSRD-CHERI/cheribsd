# $FreeBSD$

.include <src.opts.mk>

PROG=		stevie
SRCS=		stevie.c cocall.S
MAN=

#CFLAGS=		-fPIE -pie -Wno-error=deprecated-declarations
CFLAGS=		-Wno-error=deprecated-declarations
NEED_CHERI=	hybrid

WARNS?=	5

.include <bsd.prog.mk>
