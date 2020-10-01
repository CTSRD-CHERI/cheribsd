# $FreeBSD$
# Author: Shteryana Shopova <syrinx@FreeBSD.org>

BINDIR?= /usr/bin

CFLAGS+= -I. -I${.CURDIR}

.include "../Makefile.inc"
