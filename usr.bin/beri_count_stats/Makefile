#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

PROG=	beri_count_stats
MAN=
SRCS=	beri_count_stats.c
.PATH: ${SRCTOP}/lib/libstatcounters/
SRCS+=	statcounters.c
# Don't pull in the constructor function:
CFLAGS+=	-DSTATCOUNTERS_NO_CTOR_DTOR=1

NO_SHARED=yes

.include <bsd.prog.mk>
