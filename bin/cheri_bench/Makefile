# $FreeBSD$

.include <src.opts.mk>

PROG=	cheri_bench
SRCS=	cheri_bench.c

MAN=
WANT_CHERI=	yes

NO_SHARED?=	YES

LIBADD+= pthread

.if ${MACHINE_ABI:Mpurecap} && ${MK_LIBCHERI} == "yes"
LIBADD+=  cheri
.ifdef CLANG_CLEARREGS
CFLAGS+= -mllvm -cheri-use-clearregs
.endif
.endif

.include <bsd.prog.mk>
