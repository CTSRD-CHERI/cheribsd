#	@(#)Makefile	8.1 (Berkeley) 6/9/93
# $FreeBSD$

PROG=	look

.include <bsd.prog.mk>

.if defined(LIBCHERI) || (${COMPILER_TYPE} == "clang" && ${COMPILER_VERSION} >= 060000)
CFLAGS+=-Wno-tautological-constant-compare
.endif
