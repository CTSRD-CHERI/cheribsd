SRCS= caprevoke.c

INCS= caprevoke.h

CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${.CURDIR}/${MACHINE_ARCH}

SHLIB= cheri_caprevoke
SHLIB_MAJOR= 1

.if !defined(NEED_CHERI)
# XXX hubrid?
NEED_CHERI= pure
.endif

NO_WERROR=

.include <bsd.lib.mk>
