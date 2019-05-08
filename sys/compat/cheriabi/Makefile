# Makefile for syscall tables
#
# $FreeBSD$

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

all:
	@echo "make sysent only"

sysent:  cheriabi_sysent.c cheriabi_syscall.h cheriabi_proto.h cheriabi_systrace_args.c

cheriabi_sysent.c cheriabi_syscalls.c cheriabi_syscall.h cheriabi_proto.h cheriabi_systrace_args.c : \
	    ../../kern/makesyscalls.sh ../../kern/syscalls.master syscalls.conf
	sh ../../kern/makesyscalls.sh ../../kern/syscalls.master syscalls.conf

clean:
	rm -f cheriabi_sysent.c cheriabi_syscalls.c cheriabi_syscall.h cheriabi_proto.h
	rm -f cheriabi_systrace_args.c
