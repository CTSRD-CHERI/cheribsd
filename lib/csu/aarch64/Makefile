# $FreeBSD$

.PATH: ${.CURDIR:H}/common

.include <src.opts.mk>

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-DCRT_IRELOC_RELA

.if ${MACHINE_CPU:Mcheri}
CFLAGS+=	-I${.CURDIR:H}/common-cheri
.endif

CRT1OBJS+=	crt1_s.o

.include <bsd.lib.mk>
