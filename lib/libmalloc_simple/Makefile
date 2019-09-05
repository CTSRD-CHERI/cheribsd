# $FreeBSD$

.include <src.opts.mk>

LIB=	malloc_simple
SHLIB_MAJOR=	1

SRCS=	heap.c malloc.c

.if ${MACHINE_ARCH:Mmips*c*} && ${MK_CHERI_CAPREVOKE}
CFLAGS+=	-DCAPREVOKE
.endif

.include <bsd.lib.mk>
