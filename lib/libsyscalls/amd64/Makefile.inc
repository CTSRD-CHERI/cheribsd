#	from: Makefile.inc,v 1.1 1993/09/03 19:04:23 jtc Exp
# $FreeBSD$

MDASM=	vfork.S brk.S cerror.S exect.S getcontext.S pipe.S ptrace.S \
	reboot.S sbrk.S setlogin.S sigreturn.S

.PATH: ${LIBC_SRCTOP}/${LIBC_ARCH}/gen
SRCS+=	rfork_thread.S
