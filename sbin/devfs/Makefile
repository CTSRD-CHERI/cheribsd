# $FreeBSD$

PACKAGE=runtime
PROG=	devfs
SRCS=	devfs.c rule.c
MAN=	devfs.8

CHERI_NO_SHARED=	fails: ioctl DEVFSIO_RGETNEXT: No such file or directory

.include <bsd.prog.mk>
