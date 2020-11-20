# $FreeBSD$

NEED_COMPAT=	CHERI
.include <bsd.compat.mk>

PROG=	ld-cheri-elf.so.1
MAN=
MLINKS=	rtld.1 ld-cheri-elf.so.1

.PATH:  ${SRCTOP}/libexec/rtld-elf
.include "${SRCTOP}/libexec/rtld-elf/Makefile"
