# $FreeBSD$

WARNS?=		3
LIB=		statcounters
SHLIB_MAJOR=	3
SRCS+=		statcounters.c
INCS=		statcounters.h
.PATH: ${.CURDIR}/${MACHINE_CPUARCH}
CFLAGS+=	-I${.CURDIR}/${MACHINE_CPUARCH}
INCS+=	statcounters_md.h statcounters_md.inc

MAN=		libstatcounters.3

.include <bsd.lib.mk>
