
.include <src.opts.mk>

PACKAGE=	runtime
PROG=	kldxref
MAN=	kldxref.8
SRCS=	kldxref.c ef.c ef_obj.c

WARNS?=	2

.if exists(ef_${MACHINE_CPUARCH}.c)
SRCS+=	ef_${MACHINE_CPUARCH}.c
.else
SRCS+=	ef_nop.c
.endif

.if ${MACHINE_CPU:Mcheri}
.if ${MACHINE_ABI:Mpurecap}
CFLAGS+=	-DKLD_COMPAT_FREEBSD64
.else
CFLAGS+=	-DKLD_COMPAT_CHERIABI
.endif
.endif

.include <bsd.prog.mk>
