# $FreeBSD$

LIB=	cheri_support
SRCS=	libcheri_invoke_cabi.S \
	libcheri_system_stub.c

NEED_CHERI=	sandbox

NO_SHARED=yes

LIBCHERI_DIR=${.CURDIR}/../libcheri
.PATH: ${LIBCHERI_DIR}/${MACHINE_ARCH}

.include <bsd.lib.mk>
