# $FreeBSD$

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common

SRCS=		drti.c
OBJS=		${SRCS:R:S/$/.o/g}
FILES=		${OBJS}
FILESOWN=	${LIBOWN}
FILESGRP=	${LIBGRP}
FILESMODE=	${LIBMODE}
FILESDIR=	${LIBDIR}/dtrace
CLEANFILES=	${OBJS}

# These FILES qualify as libraries for the purpose of LIBRARIES_ONLY.
.undef LIBRARIES_ONLY

CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libctf/common \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common \
		-DPIC ${PICFLAG}

.include <bsd.lib.mk>
