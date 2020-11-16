# $FreeBSD$

.PATH: ${SRCTOP}/sys/contrib/openzfs/module/avl

PACKAGE=	runtime
LIB=	avl
SRCS=	avl.c
WARNS?=	3
CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
# The assert macro needs `int aok` (which is in nvpair)
LIBADD=	nvpair

# missing decleration for assfail()
NO_WERROR=

.include <bsd.lib.mk>
