# $FreeBSD$

SRCS+=	trivial-vdso_tc.c

MDASM=	Ovfork.S cerror.S exect.S

.if !defined(LIBCHERI)
MDASM+=	brk.S sbrk.S syscall.S
.else
NOASM+=	syscall.o
SRCS+=	cheri-syscall.c syscall_by_token.S
.endif

# Don't generate default code for these syscalls:
NOASM+=	vfork.o
