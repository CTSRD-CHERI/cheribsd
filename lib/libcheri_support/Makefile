# $FreeBSD$

LIB=	cheri_support
SRCS=	libcheri_invoke_cabi.S \
	libcheri_system_stub.c

CFLAGS.libcheri_invoke_cabi.S+=-DHAVE_VALID_DDC

NO_SHARED=yes

LIBCHERI_DIR=${.CURDIR}/../libcheri
.PATH: ${LIBCHERI_DIR}/${MACHINE}

.include <bsd.lib.mk>
