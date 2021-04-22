SRCS= libcheri_caprevoke.c

INCS= libcaprevoke.h
INCSDIR=	${INCLUDEDIR}/cheri

CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${.CURDIR}/${MACHINE_ARCH}

LIB=cheri_caprevoke
SHLIB= cheri_caprevoke
SHLIB_MAJOR= 1

.include <bsd.lib.mk>
