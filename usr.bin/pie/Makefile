# $FreeBSD$

.include <src.opts.mk>

PROG=	pie
MAN=

CFLAGS+=-fPIE -pie

WARNS?=	5

# PIE executables must not be built with -static
.if ${MK_CHERI_PURE} == "yes"
MK_CHERI_SHARED_PROG:=yes
.endif

.include <bsd.prog.mk>
