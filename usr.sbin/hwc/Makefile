PROG_CXX=	hwc
MAN=

CFLAGS+= -I${SRCTOP}/contrib/libucl/include
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/usr.sbin/hwc

LIBADD=	xo ucl

SRCS=	hwc.c			\
	hwc_process.c

.if ${MACHINE_CPUARCH} == "riscv"
SRCS+=	riscv/hwc_pmu.c
.endif

.include <bsd.prog.mk>
