
CFLAGS+=-I${SRCTOP}/lib/libc/${LIBSIMPLE_PRINTF_ARCH} -I${PRINTF_DIR}
PRINTF_DIR=${SRCTOP}/lib/libsimple_printf
.if exists(${PRINTF_DIR}/${MACHINE_ARCH})
LIBSIMPLE_PRINTF_ARCH=	${MACHINE_ARCH}
.else
LIBSIMPLE_PRINTF_ARCH=	${MACHINE_CPUARCH}
.endif

CSTD?=		gnu11
.ifdef SIMPLE_PRINTF_CUSTOM_WRITE_SYSCALL
# For the standalone case (no libc), we provide our own __sys_write implementation
.PATH: ${PRINTF_DIR}/${LIBSIMPLE_PRINTF_ARCH}
SRCS+=	write.S
CFLAGS+=-DSIMPLE_PRINTF_WRITE_FUNC=${SIMPLE_PRINTF_CUSTOM_WRITE_SYSCALL}
.else
# Otherwise just use the default __sys_write
CFLAGS+=-DSIMPLE_PRINTF_WRITE_FUNC=__sys_write
.endif
.PATH: ${PRINTF_DIR}
SRCS+=	simple_printf.c

CFLAGS+=	-DSIMPLE_PRINTF_PREFIX=${SIMPLE_PRINTF_PREFIX}
WARNS?=	6
