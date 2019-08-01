# $FreeBSD$

MK_PIE:=	no
.include <bsd.own.mk>

BINDIR?=	/usr/bin
WARNS?=		6

WANT_CHERI=	none

.include "${.PARSEDIR}/../Makefile.inc"
