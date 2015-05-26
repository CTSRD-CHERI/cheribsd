#	from: Makefile.inc,v 1.1 1993/09/03 19:04:23 jtc Exp
# $FreeBSD$

MDASM=	Ovfork.S brk.S cerror.S exect.S getcontext.S pipe.S ptrace.S \
	reboot.S sbrk.S setlogin.S sigreturn.S syscall.S

# Don't generate default code for these syscalls:
NOASM=	vfork.o
