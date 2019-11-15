# $FreeBSD$

.include <bsd.own.mk>

BINDIR?=	/usr/sbin
WARNS?=		6

WANT_CHERI=	none

.include "${.PARSEDIR}/../Makefile.inc"
