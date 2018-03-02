# $FreeBSD$

.include <src.opts.mk>

PROG=		coping
SRCS=		coping.c
MAN=

#CFLAGS+=	-fPIE -pie -Wno-error=deprecated-declarations -fuse-ld=lld
CFLAGS+=	-Wno-error=deprecated-declarations
NEED_CHERI=	hybrid

WARNS?=	5

.include <bsd.prog.mk>
