# $FreeBSD$

PROG?=	cheri_helloworld
SRCS=	cheri_helloworld.c

MAN=
.if ${PROG} == cheri_helloworld
.if ${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	64
.include <bsd.compat.mk>
.endif
.elif ${PROG} == cheriabi_helloworld
.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.endif
.else
.error Unknown cheri_helloworld variant ${PROG}
.endif

LIBADD=  helloworld

NO_SHARED?=	YES

.include <bsd.prog.mk>
