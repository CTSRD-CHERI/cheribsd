# $FreeBSD$

PACKAGE=lib${LIB:tl}
LIB=	BlocksRuntime
SHLIB_MAJOR=0
CFLAGS+=-I${.CURDIR}
WARNS?=	2

.PATH: ${SRCTOP}/contrib/llvm-project/compiler-rt/lib/BlocksRuntime

INCS=	Block.h Block_private.h
SRCS=	data.c runtime.c

.if ${MACHINE_ARCH:Mmips*c*}
CFLAGS+=	-Wno-error-mips-cheri-bugs
.endif

.include <bsd.lib.mk>
