# $FreeBSD$

WARNS?=		3
LIB=		statcounters
SHLIB_MAJOR=	3
SRCS+=		statcounters.c
INCS=		statcounters.h
.if ${MACHINE_ARCH:Mmips*}
INCS+=	statcounters_mips.h statcounters_mips.inc
.endif

MAN=		libstatcounters.3

.include <bsd.lib.mk>
