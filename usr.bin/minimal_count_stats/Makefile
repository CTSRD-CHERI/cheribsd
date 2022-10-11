# $FreeBSD$

PROG=	minimal_count_stats
MAN=
SRCS=	minimal_count_stats.c

.PATH: ${SRCTOP}/lib/libstatcounters/
# Note: we use the statcounters_md.h header from the sysroot so we don't have
# to add an -I flag for libstatcounters
SRCS+=	statcounters.c
# Don't pull in the constructor function:
CFLAGS+=	-DSTATCOUNTERS_NO_CTOR_DTOR=1

.include <bsd.prog.mk>
