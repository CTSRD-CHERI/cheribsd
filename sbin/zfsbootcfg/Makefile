#	@(#)Makefile	8.4 (Berkeley) 6/22/95
# $FreeBSD$

PROG=	zfsbootcfg
MAN=	zfsbootcfg.8

LIBADD+=zfsbootenv

CFLAGS+= -DIN_BASE
CFLAGS+= -I${ZFSTOP}/include
CFLAGS+= -I${ZFSTOP}/include/os/freebsd
CFLAGS+= -I${ZFSTOP}/lib/libspl/include
CFLAGS+= -I${ZFSTOP}/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${ZFSTOP}/module/icp/include
CFLAGS+= -include ${ZFSTOP}/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID
CFLAGS+= -include ${SRCTOP}/sys/modules/zfs/zfs_config.h

.include <bsd.prog.mk>
