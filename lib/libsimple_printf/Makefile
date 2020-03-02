# $FreeBSD$

.include <src.opts.mk>
MK_SSP=	no

PACKAGE=lib${LIB}
LIB=	simple_printf
MK_CHERI_SHARED=yes
SHLIB_MAJOR=    3


SIMPLE_PRINTF_PREFIX=simple
SOLINKOPTS+=	-Wl,-no-undefined -Wl,-verbose
LDFLAGS+=	-nostdlib -nodefaultlibs



.include "Makefile.inc"

.include <bsd.lib.mk>

