# $FreeBSD$

.include <bsd.own.mk>

SHLIB_MAJOR=	0
SRCS=		basic.c

# create the install directory without mtree:
PACKAGE?=	tests
FILESGROUPS+=	${PACKAGE}FILES
${PACKAGE}FILESPACKAGE=	${PACKAGE}
${PACKAGE}FILESDIR=	${TESTSDIR}

LIBDIR=		${TESTSDIR}
SHLIBDIR=	${TESTSDIR}
BINDIR=		${TESTSDIR}

.include <bsd.lib.mk>
