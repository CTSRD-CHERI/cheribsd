# $FreeBSD$

SRCS+=	trivial-vdso_tc.c

MDASM=	cerror.S \
	syscall.S \
	vfork.S

SYM_MAPS+= ${LIBC_SRCTOP}/riscv/sys/Symbol.map

.if ${MACHINE_ABI:Mpurecap}
SRCS+=	_coaccept.S _cocall.S _cogetpid2.S _cogettid.S coaccept.c cocall.c cogetpid2.c cogettid.c
.endif

# Don't generate default code for these syscalls:
NOASM+=	sbrk.o vfork.o
