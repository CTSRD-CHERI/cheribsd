# $FreeBSD$

.include <src.opts.mk>

PROG=	helloworld_static
.PATH: ${SRCTOP}/bin/helloworld
SRCS=	helloworld.c

MAN=
NEED_CHERI=	pure

MK_CHERI_SHARED_PROG:=no
NO_SHARED=yes

.include <bsd.prog.mk>
