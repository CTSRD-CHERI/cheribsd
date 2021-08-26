# $FreeBSD$

.include <src.opts.mk>

.if ${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	64
.include <bsd.compat.mk>
.endif

.include <bsd.own.mk>

BINDIR?=	/usr/sbin
WARNS?=		6

.include "${.PARSEDIR}/../Makefile.inc"
