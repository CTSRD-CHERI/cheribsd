# $FreeBSD$

.include <src.opts.mk>
MK_SSP=	no

PACKAGE=lib${LIB}
LIB=	simple_printf
MK_CHERI_SHARED=yes
SHLIB_MAJOR=    3


SIMPLE_PRINTF_PREFIX=simple
SIMPLE_PRINTF_CUSTOM_WRITE_SYSCALL=__simple_printf_sys_write
SOLINKOPTS+=	-Wl,-no-undefined -Wl,-verbose
LDFLAGS+=	-nostdlib -nodefaultlibs



.include "Makefile.inc"

.include <bsd.lib.mk>

