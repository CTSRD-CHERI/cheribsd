SRCS= caprevoke.c

INCS= caprevoke.h
INCSDIR=	${INCLUDEDIR}/cheri

CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${.CURDIR}/${MACHINE_ARCH}

LIB=cheri_caprevoke
SHLIB= cheri_caprevoke
SHLIB_MAJOR= 1

NO_WERROR=
WANT_CHERI=yes

.include "../Makefile.inc"
.include <bsd.lib.mk>
