# $FreeBSD$

NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
SHLIB=		wrong_size_purecap
.include <src.opts.mk>
# Invert the CHERI bits MK_ flags to build a library for the wrong target:
.if ${MK_CHERI128} != "no"
MK_CHERI256:=yes
MK_CHERI128:=no
.elif ${MK_CHERI256} != "no"
MK_CHERI128:=yes
MK_CHERI256:=no
.else
.error "Must build for either CHERI 128/256 (or is 256 gone?)"
.endif
# Don't link against incompatible csu files
LDFLAGS+=-nodefaultlibs -nostartfiles
.include "../basic-lib.mk"
