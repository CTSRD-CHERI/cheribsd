# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	mtree

# NOTE: BSD.debug.dist is unconditionally installed for developer ease-of-use.
FILES=	\
	BSD.debug.dist \
	BSD.include.dist \
	BSD.root.dist \
	${_BSD.lib32.dist} \
	${_BSD.lib64.dist} \
	${_BSD.lib64c.dist} \
	${_BSD.sendmail.dist} \
	${_BSD.tests.dist} \
	BSD.usr.dist \
	BSD.var.dist

.if ${MK_LIB64C} != "no"
_BSD.lib64c.dist=	BSD.lib64c.dist
.endif
.if ${MK_LIB32} != "no"
_BSD.lib32.dist=	BSD.lib32.dist
.endif
.if ${MK_LIB64} != "no"
_BSD.lib64.dist=	BSD.lib64.dist
.endif
.if ${MK_SENDMAIL} != "no"
_BSD.sendmail.dist=	BSD.sendmail.dist
.endif
.if ${MK_TESTS} != "no"
_BSD.tests.dist=	BSD.tests.dist
.endif

NO_OBJ=
FILESDIR= /etc/mtree

.include <bsd.prog.mk>
