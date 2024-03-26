# $FreeBSD$

.include <src.opts.mk>
MK_SSP=	no
OPT_INIT_ALL=	none

PACKAGE=lib${LIB}
LIB=	simple_printf
MK_CHERI_SHARED=yes
SHLIB_MAJOR=    3


SIMPLE_PRINTF_PREFIX=simple
SOLINKOPTS+=	-Wl,-no-undefined -Wl,-verbose
LDFLAGS+=	-nostdlib -nodefaultlibs

.include "Makefile.inc"

# For the standalone case (no libc), we provide our own __sys_write implementation
CFLAGS+=-ffreestanding -fno-builtin
CFLAGS+=-DSIMPLE_PRINTF_AVOID_LIBC_FUNCTIONS=1
CFLAGS+=-I${SRCTOP}/lib/libc/${LIBSIMPLE_PRINTF_ARCH}
.if exists(${PRINTF_DIR}/${MACHINE_ARCH})
LIBSIMPLE_PRINTF_ARCH=	${MACHINE_ARCH}
.else
LIBSIMPLE_PRINTF_ARCH=	${MACHINE_CPUARCH}
.endif

.PATH: ${PRINTF_DIR}/${LIBSIMPLE_PRINTF_ARCH}
SRCS+=	write.S
CFLAGS+=-DSIMPLE_PRINTF_WRITE_FUNC=__simple_printf_sys_write

.include <bsd.lib.mk>

