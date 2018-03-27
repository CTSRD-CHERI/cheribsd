# $FreeBSD$

.include <src.opts.mk>

PROG=		copong
SRCS=		copong.c
MAN=

CFLAGS+=	-fPIE -pie -Wno-error=deprecated-declarations -fuse-ld=lld
NEED_CHERI=	hybrid
MK_CHERI_SHARED_PROG:=yes

WARNS?=	5

.include <bsd.prog.mk>
