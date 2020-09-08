# $FreeBSD$

PROG=	ld-elf-debug.so.1
MAN=
MLINKS=	rtld.1 ld-elf-debug.so.1.1

RTLD_DEBUG_VERBOSE?=	3
BUILD_RTLD_DEBUG:=	yes
MK_TESTS:=	no

.PATH:  ${SRCTOP}/libexec/rtld-elf
.include "${SRCTOP}/libexec/rtld-elf/Makefile"

CFLAGS+=-O0 -ggdb
