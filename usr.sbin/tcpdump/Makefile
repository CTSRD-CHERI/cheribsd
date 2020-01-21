#	@(#)Makefile	0.1 (RGrimes) 4/4/93
# $FreeBSD$

.include <src.opts.mk>

SUBDIR=	tcpdump

.if ${MK_LIBCHERI} != "no"
SUBDIR+=	cheri_tcpdump
.endif

.include <bsd.subdir.mk>
