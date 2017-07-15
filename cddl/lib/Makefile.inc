# $FreeBSD$

SHLIBDIR?= /lib
SHLIB_MAJOR?= 2

.if ${MK_CHERI_PURE} == "yes"
WANT_CHERI?=	pure
.endif

.include "../Makefile.inc"
