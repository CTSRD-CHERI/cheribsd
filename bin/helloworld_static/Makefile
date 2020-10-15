# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.endif

PROG=	helloworld_static
.PATH: ${SRCTOP}/bin/helloworld
SRCS=	helloworld.c

MAN=

NO_SHARED=yes

.include <bsd.prog.mk>
