#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

.include <src.opts.mk>

PROG=	logger

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
.endif

# XXX: don't bother with the extra fork()+socket I/O here to speed up running
# the testsuite
.if 0 && ${MK_CASPER} != "no"
LIBADD+=        casper
LIBADD+=        cap_syslog
CFLAGS+=-DWITH_CASPER
.endif

.include <bsd.prog.mk>
