.PATH: ${.CURDIR:H}/common

.include <src.opts.mk>

CFLAGS+=	-I${.CURDIR}

.if ${MACHINE_CPU:Mcheri}
CFLAGS+=	-I${.CURDIR:H}/common-cheri

NO_WCAST_ALIGN=
.endif

CRT1SRC=	crt1_s.S
CRT1OBJ=	crt1_c.o

.include <bsd.lib.mk>
