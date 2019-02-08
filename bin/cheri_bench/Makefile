# $FreeBSD$

.include <bsd.own.mk>

PROG=	cheri_bench
SRCS=	cheri_bench.c

MAN=
WANT_CHERI=	yes

NO_SHARED?=	YES

NO_WERROR=	YES

LIBADD+= pthread

.if ${MACHINE_ARCH:Mmips*c*} || ${MK_CHERI} != "no"
LIBADD+=  cheri
.ifdef CLANG_CLEARREGS
CFLAGS+= -mllvm -cheri-use-clearregs
.endif
.endif

.include <bsd.prog.mk>
