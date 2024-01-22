.include <bsd.own.mk>

SHLIB_MAJOR=	0

# create the install directory without mtree:
PACKAGE?=	tests
FILESGROUPS+=	${PACKAGE}FILES
${PACKAGE}FILESPACKAGE=	${PACKAGE}
${PACKAGE}FILESDIR=	${TESTSDIR}

LIBDIR=		${TESTSDIR}
SHLIBDIR=	${TESTSDIR}
BINDIR=		${TESTSDIR}
DIRS+=	TESTSDIR
.include <bsd.lib.mk>

# ensure the target directory exists before installing
_libinstall: installdirs
