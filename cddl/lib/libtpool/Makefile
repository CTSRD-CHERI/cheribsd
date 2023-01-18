# $FreeBSD$

.PATH: ${ZFSTOP}/lib/libtpool
.PATH: ${ZFSTOP}/include


LIB=	tpool
LIBADD=	spl
PACKAGE=	runtime

INCS=	thread_pool_impl.h
SRCS=	thread_pool.c

WARNS?=	2
CSTD=	c99
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

.include <bsd.lib.mk>
