# $FreeBSD$

MK_PIE:=	no
.include <bsd.own.mk>

BINDIR?=	/usr/bin
WARNS?=		6

.include "${.PARSEDIR}/../Makefile.inc"
