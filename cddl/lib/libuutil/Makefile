# $FreeBSD$

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/lib/libuutil/common
.PATH: ${SRCTOP}/sys/cddl/contrib/opensolaris/common/avl

PACKAGE=	runtime
LIB=	uutil
SRCS=	avl.c \
	uu_alloc.c \
	uu_avl.c \
	uu_dprintf.c \
	uu_ident.c \
	uu_list.c \
	uu_misc.c \
	uu_open.c \
	uu_pname.c \
	uu_strtoint.c

WARNS?=	1
CFLAGS+= -DNATIVE_BUILD
CFLAGS+= -I${SRCTOP}/cddl/contrib/opensolaris/lib/libuutil/common
CFLAGS+= -I${SRCTOP}/sys/cddl/compat/opensolaris
CFLAGS+= -I${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${SRCTOP}/cddl/contrib/opensolaris/head

# The aok vairable used by assert() is defined in
# sys/cddl/contrib/opensolaris/common/nvpair/opensolaris_nvpair.c so we need
# to link against nvpair in order to get size information for that file
# (at least for libcheri)
LIBADD=	nvpair

.include <bsd.lib.mk>
