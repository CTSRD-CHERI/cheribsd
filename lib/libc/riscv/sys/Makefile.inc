# $FreeBSD$

SRCS+=	trivial-vdso_tc.c

MDASM=	cerror.S \
	syscall.S \
	vfork.S

SYM_MAPS+= ${LIBC_SRCTOP}/riscv/sys/Symbol.map

.if ${MK_CHERI} == "yes"
SRCS+=	_coaccept.S _cocall.S
.endif

# Don't generate default code for these syscalls:
NOASM+=	sbrk.o vfork.o
