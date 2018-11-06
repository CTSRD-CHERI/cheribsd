#	@(#)Makefile	8.2 (Berkeley) 3/21/94
# $FreeBSD$
#
# Makefile for init_sysent

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

all:
	@echo "make sysent only"

sysent: init_sysent.c syscalls.c ../sys/syscall.h ../sys/syscall.mk \
../sys/sysproto.h ../sys/sysargmap.h

init_sysent.c syscalls.c systrace_args.c ../sys/syscall.h \
../sys/syscall.mk ../sys/sysproto.h ../sys/sysargmap.h: makesyscalls.sh syscalls.master \
capabilities.conf syscalls.conf
	sh makesyscalls.sh syscalls.master syscalls.conf
