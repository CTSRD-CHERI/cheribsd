# $FreeBSD$
# We build a statically linked non-CHERI shell for atf-sh tests
# This is noticeably faster on QEMU since we don't have to emulate
# CHERI instructions (shouldn't make much of a difference on HW though).
# It also means we don't have to process capability relocations on startup.
.include <src.opts.mk>

.if ${MACHINE_ABI:Mpurecap} && !make(build-tools)
NEED_COMPAT=	64
.include <bsd.compat.mk>
.endif

PROG=	sh_static
NO_SHARED=	yes
MAN=

.include	"${SRCTOP}/bin/sh/Makefile"
