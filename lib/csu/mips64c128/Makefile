# $FreeBSD$

.PATH:	${.CURDIR}/../common-cheri ${.CURDIR}/../common

CFLAGS+=	-DCRT_IRELOC_SUPPRESS

CFLAGS+=	-mxgot -mllvm -mxmxgot

.include <bsd.lib.mk>
