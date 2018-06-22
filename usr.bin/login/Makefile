# 	@(#)Makefile	8.1 (Berkeley) 7/19/93
# $FreeBSD$

.include <src.opts.mk>

.if ${MK_CHERI_SHARED_PROG} == "no"
# can't be static (missing pam_self)
WANT_CHERI=none
.endif

PROG=	login
SRCS=	login.c login_fbtab.c
CFLAGS+=-DLOGALL
LIBADD=	util pam

WARNS?=	5

.if ${MK_AUDIT} != "no"
SRCS+=	login_audit.c
CFLAGS+= -DUSE_BSM_AUDIT
LIBADD+=	bsm
.endif

.if ${MK_SETUID_LOGIN} != "no"
BINOWN=	root
BINMODE=4555
PRECIOUSPROG=
.endif

.include <bsd.prog.mk>
