
PRINTF_DIR=${SRCTOP}/lib/libsimple_printf
.PATH: ${PRINTF_DIR}
WARNS?=	6
CSTD?=		gnu11
CFLAGS+=	-I${PRINTF_DIR}
CFLAGS+=	-DSIMPLE_PRINTF_PREFIX=${SIMPLE_PRINTF_PREFIX}
SRCS+=	simple_printf.c

# To reuse the printfcommon.h code for printing capabilities:
CFLAGS.simple_printf.c+=	-DIN_LIBSIMPLE_PRINTF=1
CFLAGS.simple_printf.c+=	-I${SRCTOP}/lib/libc/stdio
