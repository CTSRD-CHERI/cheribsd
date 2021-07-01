# $FreeBSD$

COMPARTMENT_NAME=	helloworld

# XXXBD: stuff below this line should come from a bsd.c9t.mk

LDFLAGS+=	-Wl,-T,${.CURDIR}/../../libc_cheri/sandbox.ld \
		-nostdlib

LIBADD=	c_cheri

PROG=	${COMPARTMENT_NAME}.co.0
SRCS=	${COMPARTMENT_NAME}.c
MAN=

.ifdef COMPAT_CHERI
BINDIR=	/usr/libcheri
.else
BINDIR=	/usr/lib
.endif

.include <bsd.prog.mk>
