# $FreeBSD$

.PATH: ${.CURDIR:H}/common

.include <src.opts.mk>

.if ${MACHINE_CPU:Mcheri}
CFLAGS+=	-I${.CURDIR:H}/common-cheri
.endif

CRT1OBJS+=	crt1_s.o

.include <bsd.lib.mk>
