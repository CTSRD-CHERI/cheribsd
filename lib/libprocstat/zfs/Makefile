# $FreeBSD$

.PATH: ${.CURDIR:H}

SRCS=	zfs_defs.c
OBJS=	zfs_defs.o
WARNS?=	1


CFLAGS+= -DIN_BASE -D__KERNEL__ -D_KERNEL -I. -I${.CURDIR}
CFLAGS+= -I${ZFSTOP}/include
CFLAGS+= -I${ZFSTOP}/include/os/freebsd/spl
CFLAGS+= -I${ZFSTOP}/include/os/freebsd/
CFLAGS+= -I${ZFSTOP}/include/os/freebsd/zfs
CFLAGS+= -I${SRCTOP}/sys/contrib/ck/include

CFLAGS+= -I${SRCTOP}/sys -I.  -I..
CFLAGS+= -I${ZFSTOP}/module/icp/include
CFLAGS+= -include ${ZFSTOP}/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID -D_SYS_VMEM_H_ -UKLD_TIED -DKLD_MODULE

CFLAGS+= -fno-builtin -nostdlib

all: ${OBJS}
CLEANFILES= ${OBJS}

.include <bsd.lib.mk>
