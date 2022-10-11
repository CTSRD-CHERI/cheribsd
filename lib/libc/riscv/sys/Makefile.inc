# $FreeBSD$

SRCS+=	__vdso_gettc.c \
	sched_getcpu_gen.c

MDASM=	cerror.S \
	syscall.S \
	vfork.S

SYM_MAPS+= ${LIBC_SRCTOP}/riscv/sys/Symbol.map

.if ${MACHINE_ABI:Mpurecap}
SRCS+=	_coaccept.S _cocall.S _cogetpid2.S _cogettid.S coaccept.c cocall.c cogetpid2.c cogettid.c
.endif

# Don't generate default code for these syscalls:
NOASM+=	sbrk.o vfork.o
