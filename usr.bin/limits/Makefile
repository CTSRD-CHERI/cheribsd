# $FreeBSD$

.include <src.opts.mk>

PROG=	limits
LIBADD=	util

CHERI_NO_SHARED=	fails

.if ${MK_TESTS} != "no"
SUBDIR+=	tests
.endif

.include <bsd.prog.mk>
