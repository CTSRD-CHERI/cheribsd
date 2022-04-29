# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	64C
.include <bsd.compat.mk>
.endif

PROG=	helloworld

MAN=

.include <bsd.prog.mk>
