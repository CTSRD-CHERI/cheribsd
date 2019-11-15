# $FreeBSD$

.if ${MACHINE_ARCH:Mmips*c*}
PROG=ld-elf-debug.so.1
.else
PROG=ld-cheri-elf-debug.so.1
.endif
RTLD_DEBUG_VERBOSE?=3
BUILD_RTLD_DEBUG:=yes
MK_TESTS:=no
.include "../rtld-cheri-elf/Makefile"
CFLAGS+=-O0 -ggdb
