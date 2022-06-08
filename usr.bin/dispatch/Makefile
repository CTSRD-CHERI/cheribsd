# $FreeBSD$

.include <src.opts.mk>

.PATH: ${SRCTOP}/sys/riscv/cheri

PROG=	dispatch
SRCS=	dispatch.c cheri_cocall.S cheri_coaccept.S

# XXX this is required to make the *.S build
CFLAGS.cheri_cocall.S+=	-D_KERNEL
CFLAGS.cheri_coaccept.S+= -D_KERNEL

WARNS?=	5

.include <bsd.prog.mk>
