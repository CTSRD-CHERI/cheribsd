# $FreeBSD$

.include <bsd.own.mk>
WANT_CHERI=	none
LIB=		pythagoras
SHLIB_MAJOR=	0

LIBDIR=		${TESTSBASE}/libexec/rtld-elf
SHLIBDIR=	${TESTSBASE}/libexec/rtld-elf

SRCS=		pythagoras.c

WARNS?=		6
LIBADD=		m

.include <bsd.lib.mk>
