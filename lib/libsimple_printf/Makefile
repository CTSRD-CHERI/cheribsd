# $FreeBSD$
PACKAGE=lib${LIB}
LIB=	simple_printf
MK_CHERI_SHARED=yes

SIMPLE_PRINTF_PREFIX=simple
SOLINKOPTS+=	-Wl,-no-undefined -Wl,-verbose
LDFLAGS+=	-nostdlib


.include "Makefile.inc"

.include <bsd.lib.mk>

