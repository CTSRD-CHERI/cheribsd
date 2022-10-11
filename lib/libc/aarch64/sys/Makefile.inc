# $FreeBSD$

MIASM:=	${MIASM:Nfreebsd[467]_*}

SRCS+=	__vdso_gettc.c \
	sched_getcpu_gen.c

MDASM=	cerror.S \
	syscall.S \
	vfork.S

SYM_MAPS+= ${LIBC_SRCTOP}/aarch64/sys/Symbol.map

.if ${MACHINE_ABI:Mpurecap}
SRCS+=	_coaccept.S _cocall.S
.endif

# Don't generate default code for these syscalls:
NOASM+=	sbrk.o \
	vfork.o
