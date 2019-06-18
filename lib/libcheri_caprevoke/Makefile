SRCS= caprevoke.c

INCS= caprevoke.h

CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${.CURDIR}/${MACHINE_ARCH}

LIB=cheri_caprevoke
SHLIB= cheri_caprevoke
SHLIB_MAJOR= 1

.if !defined(NEED_CHERI)
# XXX hybrid? both?
NEED_CHERI= pure
.endif

NO_WERROR=

.include <bsd.lib.mk>
