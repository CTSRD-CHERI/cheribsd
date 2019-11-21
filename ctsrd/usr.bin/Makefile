# $FreeBSD$

.include <src.opts.mk>

SUBDIR=	browser \
	writefile

.if ${MK_CHERI} != "no"
SUBDIR+=	cheripoint
.endif

.include <bsd.subdir.mk>
