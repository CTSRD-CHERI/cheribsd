# $FreeBSD$

#NO_WERROR=
PROG=	truss
SRCS=	main.c setup.c syscalls.c

LIBADD=	sysdecode

#CFLAGS+= -I${.CURDIR} -I. -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/sys

CHERI_UINTCAP_MODE=addr

.include <bsd.prog.mk>
