# $FreeBSD$

SRCS+=	trivial-vdso_tc.c

MDASM=	Ovfork.S cerror.S syscall.S

# Don't generate default code for these syscalls:
NOASM+=	vfork.o

# This is needed to export _exit from libsyscalls
SYM_MAPS+= ${LIBC_SRCTOP}/mips/sys/Symbol.map

.if ${MACHINE_ABI:Mpurecap}
SRCS+=	_coaccept.S _cocall.S coaccept.c cocall.c
.endif
