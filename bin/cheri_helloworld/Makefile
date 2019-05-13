# $FreeBSD$

PROG?=	cheri_helloworld
SRCS=	cheri_helloworld.c

MAN=
.if ${PROG} == cheri_helloworld
NEED_CHERI=	hybrid
.elif ${PROG} == cheriabi_helloworld
WANT_CHERI=	pure
.else
.error Unknown cheri_helloworld variant ${PROG}
.endif

LIBADD=  helloworld

NO_SHARED?=	YES

NO_WERROR=	YES

.include <bsd.prog.mk>
