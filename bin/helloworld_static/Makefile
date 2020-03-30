# $FreeBSD$

.include <src.opts.mk>

PROG=	helloworld_static
.PATH: ${SRCTOP}/bin/helloworld
SRCS=	helloworld.c

MAN=
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>

NO_SHARED=yes

.include <bsd.prog.mk>
