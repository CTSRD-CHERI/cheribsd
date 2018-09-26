#
# $FreeBSD$
#
.PATH: ${.CURDIR}/../common
SRCS=	crt_init_globals.c			\
	crt_invoke.S				\
	crt_rtld.S				\
	crtbeginC.c				\
	crtendC.c
FILES=	${SRCS:C/.[cS]$/.o/}

FILESOWN=       ${LIBOWN}
FILESGRP=       ${LIBGRP}
FILESMODE=      ${LIBMODE}
FILESDIR=       ${LIBDIR}
# These FILES qualify as libraries for the purpose of LIBRARIES_ONLY.
.undef LIBRARIES_ONLY
CLEANFILES=	${FILES}
CFLAGS+=-mxgot -mllvm -mxmxgot

NEED_CHERI=	pure

.include <bsd.lib.mk>
