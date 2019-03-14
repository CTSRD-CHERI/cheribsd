# $FreeBSD$

COMPARTMENT_NAME=	helloworld

# XXXBD: stuff below this line should come from a bsd.c9t.mk

LDFLAGS+=	-Wl,-T,${.CURDIR}/../../libc_cheri/sandbox.ld \
		-Wl,-z,notext \
		-nostdlib

LIBADD=	c_cheri

NEED_CHERI=sandbox
PROG=	${COMPARTMENT_NAME}.co.0
SRCS=	${COMPARTMENT_NAME}.c
MAN=

BINDIR=	/usr/libcheri

.include <bsd.prog.mk>
