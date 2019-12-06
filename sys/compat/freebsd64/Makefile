# Makefile for syscall tables
#
# $FreeBSD$

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

all:
	@echo "make sysent only"

sysent:  freebsd64_sysent.c freebsd64_syscall.h freebsd64_proto.h freebsd64_systrace_args.c

freebsd64_sysent.c freebsd64_syscalls.c freebsd64_syscall.h freebsd64_proto.h freebsd64_systrace_args.c : \
	    ../../tools/makesyscalls.lua ../../kern/syscalls.master ${.CURDIR}/syscalls.conf
	${LUA} ../../tools/makesyscalls.lua ../../kern/syscalls.master ${.CURDIR}/syscalls.conf

clean:
	rm -f freebsd64_sysent.c freebsd64_syscalls.c freebsd64_syscall.h freebsd64_proto.h
	rm -f freebsd64_systrace_args.c
