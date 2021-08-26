# $FreeBSD$

.include <src.opts.mk>

.if ${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	64
.include <bsd.compat.mk>
.endif

SHLIB=		basic_hybrid
.include "../basic-lib.mk"
