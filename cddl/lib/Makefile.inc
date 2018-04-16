# $FreeBSD$

SHLIBDIR?= /lib
SHLIB_MAJOR?= 2

.ifdef LIBCHERI
CFLAGS+=	-Wno-cheri-bitwise-operations
.endif

.include "../Makefile.inc"
