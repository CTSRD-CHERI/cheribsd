# $FreeBSD$

PROG=	mount_smbfs
SRCS=	mount_smbfs.c getmntopts.c
MAN=	mount_smbfs.8

# Since https://github.com/CTSRD-CHERI/cheribsd/pull/282 we only support CheriABI
WANT_CHERI=pure

MOUNTDIR=	${SRCTOP}/sbin/mount
CONTRIBDIR=	${SRCTOP}/contrib/smbfs
CFLAGS+=	-DSMBFS -I${MOUNTDIR} -I${CONTRIBDIR}/include

LIBADD=	smb

.PATH:	${CONTRIBDIR}/mount_smbfs
.PATH:  ${MOUNTDIR}

.include <bsd.prog.mk>
