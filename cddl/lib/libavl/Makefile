# $FreeBSD$

.PATH: ${SRCTOP}/sys/cddl/contrib/opensolaris/common/avl

PACKAGE=	runtime
LIB=	avl
SRCS=	avl.c
WARNS?=	3
CFLAGS+= -I${SRCTOP}/sys/cddl/compat/opensolaris
CFLAGS+= -I${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common
# The assert macro needs `int aok` (which is in nvpair)
LIBADD=	nvpair

.include <bsd.lib.mk>
