SYSDIR?=	${SRCTOP}/sys

.PATH:		${SYSDIR}/cddl/dev/cbt \
		${SYSDIR}/cddl/dev/cbt/${MACHINE_CPUARCH}

KMOD=		cbt
SRCS=		cbt.c
SRCS+=		cbt_isa.c

CFLAGS+=	${OPENZFS_CFLAGS}
CFLAGS+=	-I${SYSDIR}/cddl/dev/cbt
CFLAGS+=	-I${SYSDIR}/cddl/dev/dtrace

.include <bsd.kmod.mk>
