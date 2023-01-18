# $FreeBSD$

.PATH: ${ZFSTOP}/lib/libuutil

PACKAGE=	runtime
LIB=	uutil
SRCS=\
	uu_alloc.c \
	uu_avl.c \
	uu_ident.c \
	uu_list.c \
	uu_misc.c \
	uu_string.c

WARNS?=	2
CFLAGS+= -DIN_BASE
CFLAGS+= -I${ZFSTOP}/include
CFLAGS+= -I${ZFSTOP}/lib/libspl/include/
CFLAGS+= -I${ZFSTOP}/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -include ${ZFSTOP}/include/os/freebsd/spl/sys/ccompile.h

LIBADD= avl spl

# The aok vairable used by assert() is defined in
# sys/cddl/contrib/opensolaris/common/nvpair/opensolaris_nvpair.c so we need
# to link against nvpair in order to get size information for that file
# (at least for purecap)
LIBADD+=	nvpair

.include <bsd.lib.mk>
