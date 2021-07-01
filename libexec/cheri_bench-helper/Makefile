#
# $FreeBSD$
#

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.endif

PROG=	cheri_bench-helper
SRCS=	cheri_bench-helper.c

INCS=	cheri_bench-helper.h

LDFLAGS+=	-Wl,-T,${.CURDIR}/../../lib/libc_cheri/sandbox.ld \
		-nostdlib
MAN=

LIBADD=	c_cheri

NO_SHARED=	yes

.include <bsd.prog.mk>
