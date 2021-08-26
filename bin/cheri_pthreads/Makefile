# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.endif

PROG?=	cheri_pthreads
SRCS?=	cheri_pthreads.c

MAN=

LIBADD=	pthread

NO_SHARED=	YES

.include <bsd.prog.mk>
