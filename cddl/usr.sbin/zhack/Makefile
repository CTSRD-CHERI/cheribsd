# $FreeBSD$

.PATH: ${ZFSTOP}/cmd

PROG=	zhack
MAN=

WARNS?=	0
CSTD=	c99

WARNS?=	2
CFLAGS+= -DIN_BASE
CFLAGS+= -I${ZFSTOP}/include
CFLAGS+= -I${ZFSTOP}/lib/libspl/include/
CFLAGS+= -I${ZFSTOP}/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${ZFSTOP}/module/icp/include
CFLAGS+= -include ${ZFSTOP}/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID
CFLAGS+= -include ${SRCTOP}/sys/modules/zfs/zfs_config.h


LIBADD=	nvpair zfs spl zutil zpool

CFLAGS+=	-DDEBUG=1
#DEBUG_FLAGS+=	-g

.include <bsd.prog.mk>
