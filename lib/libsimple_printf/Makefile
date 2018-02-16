# $FreeBSD$
PACKAGE=lib${LIB}
SHLIB_NAME=	libsimple_printf.so.1
MK_CHERI_SHARED=yes

SIMPLE_PRINTF_PREFIX=simple
SOLINKOPTS+=	-Wl,-no-undefined -Wl,-verbose
LDFLAGS+=	-nostdlib -nodefaultlibs



.include "Makefile.inc"

.include <bsd.lib.mk>

