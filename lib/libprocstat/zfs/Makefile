.PATH: ${.CURDIR:H}

SRCS=	zfs_defs.c
OBJS=	zfs_defs.o
WARNS?=	1

FORTIFY_SOURCE=	0

# We fake a kernel compilation environment in order to get the definition for
# 'zpool_t'.
CFLAGS+= -DIN_BASE -D__KERNEL__ -D_KERNEL -UKLD_TIED -DKLD_MODULE
CFLAGS+= -DHAVE_ISSETUGID -D_SYS_VMEM_H_

CFLAGS+= -fno-builtin -nostdlib

CFLAGS+= -I${.CURDIR}
CFLAGS+= -I${ZFSTOP}/include
CFLAGS+= -I${ZFSTOP}/include/os/freebsd/spl
CFLAGS+= -I${ZFSTOP}/include/os/freebsd/zfs
CFLAGS+= -I${ZFSTOP}/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys/contrib/ck/include
CFLAGS+= -I${ZFSTOP}/module/icp/include
CFLAGS+= -I${SRCTOP}/sys -I. -I..

CFLAGS+= -include ${ZFSTOP}/include/os/freebsd/spl/sys/ccompile.h

all: ${OBJS}
CLEANFILES= ${OBJS}

.include <bsd.lib.mk>
