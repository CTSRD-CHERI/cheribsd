# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.endif

PROG=	cheribsdtest-purecap

.include "../Makefile.purecap"
