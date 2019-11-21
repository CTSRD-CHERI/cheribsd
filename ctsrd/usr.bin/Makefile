# $FreeBSD$

.include <src.opts.mk>

SUBDIR=	browser \
	writefile

.if ${MK_CHERI} != "no"
SUBDIR+=	cheripoint \
		pictview
.endif

.include <bsd.subdir.mk>
