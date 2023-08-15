# $FreeBSD$

PROG_CXX=	hwt
MAN=

CFLAGS+= -I${SRCTOP}/lib/libpmcstat

LIBADD= elf pmcstat xo util

SRCS=	hwt.c			\
	hwt_elf.c		\
	hwt_process.c		\
	hwt_record.c		\
	libpmcstat_stubs.c

.if ${MACHINE_CPUARCH} == "aarch64"
SRCS+=	hwt_coresight.c
LIBADD+= opencsd
.endif

.include <bsd.prog.mk>
