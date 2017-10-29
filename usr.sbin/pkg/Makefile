# $FreeBSD$

PROG=	pkg
SRCS=	pkg.c dns_utils.c config.c
MAN=	pkg.7

CHERI_NO_SHARED=	fails: permit execute violation

CFLAGS+=-I${SRCTOP}/contrib/libucl/include
.PATH:	${SRCTOP}/contrib/libucl/include
LIBADD=	archive fetch ucl sbuf crypto ssl

.include <bsd.prog.mk>
