# $FreeBSD$

SHLIBDIR?=      /lib

.include <src.opts.mk>

PACKAGE=	runtime

LIBXOSRC=	${SRCTOP}/contrib/libxo

.if !defined(NO_SHARED)
SUBDIR = csv
.endif

.include <bsd.subdir.mk>
