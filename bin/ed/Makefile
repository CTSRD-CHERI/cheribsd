# $FreeBSD$

.include <src.opts.mk>

PACKAGE=runtime
PROG=	ed
SRCS=	buf.c glbl.c io.c main.c re.c sub.c undo.c
LINKS=	${BINDIR}/ed ${BINDIR}/red
MLINKS=	ed.1 red.1

NO_WERROR=	# Surpress -Wclobbered error in base gcc

.include <bsd.prog.mk>
