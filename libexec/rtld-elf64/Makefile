# $FreeBSD$

NEED_COMPAT=	64
.include <bsd.compat.mk>

PROG=	ld-elf64.so.1
MAN=
# XXX: should be "rtld.1 ld-elf64.so.1" but rtld.1 isn't installed by
# rtld-cheri-elf.
MLINKS=

.PATH:  ${SRCTOP}/libexec/rtld-elf
.include "${SRCTOP}/libexec/rtld-elf/Makefile"
