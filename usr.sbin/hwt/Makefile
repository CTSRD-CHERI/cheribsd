# $FreeBSD$

PROG_CXX=	hwt
MAN=

CFLAGS+= -I${SRCTOP}/lib/libpmcstat

LIBADD= elf opencsd pmcstat

SRCS=	hwt.c			\
	hwt_coresight.c		\
	hwt_elf.c		\
	hwt_process.c		\
	hwt_record.c		\
	libpmcstat_stubs.c

.include <bsd.prog.mk>
