# $FreeBSD$

PROG?=		ldd
SRCS=		ldd.c
.if ${MACHINE_CPUARCH} == "i386"
SRCS+=		sods.c
.endif

CFLAGS+=	-I${SRCTOP}/libexec/rtld-elf

.include <bsd.prog.mk>
