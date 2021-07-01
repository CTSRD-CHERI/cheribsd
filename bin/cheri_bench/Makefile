# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.endif

PROG=	cheri_bench
SRCS=	cheri_bench.c

MAN=

NO_SHARED?=	YES

LIBADD+= pthread

.if ${MACHINE_ABI:Mpurecap} && ${MK_LIBCHERI} == "yes"
LIBADD+=  cheri
.ifdef CLANG_CLEARREGS
CFLAGS+= -mllvm -cheri-use-clearregs
.endif
.endif

.include <bsd.prog.mk>
