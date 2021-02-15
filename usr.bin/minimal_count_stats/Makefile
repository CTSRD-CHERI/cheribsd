# $FreeBSD$

PROG=	minimal_count_stats
MAN=
SRCS=	minimal_count_stats.c

.if ${MACHINE_ARCH:Mmips64*}
# Keep the old name for old scripts
LINKS+=	${BINDIR}/minimal_count_stats ${BINDIR}/beri_count_stats
.endif

.PATH: ${SRCTOP}/lib/libstatcounters/
# Note: we use the statcounters_md.h header from the sysroot so we don't have
# to add an -I flag for libstatcounters
SRCS+=	statcounters.c
# Don't pull in the constructor function:
CFLAGS+=	-DSTATCOUNTERS_NO_CTOR_DTOR=1

.include <bsd.prog.mk>
