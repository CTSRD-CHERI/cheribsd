# $FreeBSD$

.include <bsd.own.mk>
WANT_CHERI=	none
PROG=		target
BINDIR=		${TESTSBASE}/libexec/rtld-elf

WARNS?=		3
CFLAGS+=	-I${.CURDIR}/../libpythagoras

LDFLAGS+=	-L${.OBJDIR}/../libpythagoras
DPADD+=		${.OBJDIR}/../libpythagoras/libpythagoras.a
LDADD=		-lpythagoras

MAN=

.include <bsd.prog.mk>
