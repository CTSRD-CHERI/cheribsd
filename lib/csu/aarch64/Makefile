# $FreeBSD$

.PATH: ${.CURDIR:H}/common

CFLAGS+=	-DCRT_IRELOC_SUPPRESS
CFLAGS+=	-I${.CURDIR:H}/common-cheri

CRT1OBJS+=	crt1_s.o

.include <bsd.lib.mk>
