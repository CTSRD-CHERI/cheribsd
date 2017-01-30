# $FreeBSD$

LIB=	cheri_support
SRCS=	cheri_invoke_cabi.S \
	cheri_system_stub.c

NEED_CHERI=	sandbox
# cheri_invoke_cabi.S is not PIC so creating a shared library will not work
NO_SHARED=	yes

LIBCHERI_DIR=${.CURDIR}/../libcheri
.PATH: ${LIBCHERI_DIR}/${MACHINE_ARCH}

.include <bsd.lib.mk>
