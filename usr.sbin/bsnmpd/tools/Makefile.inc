# $FreeBSD$
# Author: Shteryana Shopova <syrinx@FreeBSD.org>

BINDIR?= /usr/bin

CFLAGS+= -I. -I${.CURDIR}

WARNS?=		6

.include "../Makefile.inc"
