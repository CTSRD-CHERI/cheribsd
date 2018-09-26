# $FreeBSD$

PACKAGE=lib${LIB:tl}
LIB=	BlocksRuntime
SHLIB_MAJOR=0
CFLAGS+=-I${.CURDIR}
WARNS?=	2

.PATH: ${SRCTOP}/contrib/compiler-rt/lib/BlocksRuntime

INCS=	Block.h Block_private.h
SRCS=	data.c runtime.c

.if ${MACHINE_ARCH:Mmips*c128} || ${MACHINE_ARCH:Mmips*c256}
CFLAGS+=	-Wno-error-mips-cheri-bugs
.endif

.include <bsd.lib.mk>
