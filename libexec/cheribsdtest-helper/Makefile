#
# $FreeBSD$
#

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.endif

PROG=	cheribsdtest-helper
SRCS=	cheribsdtest-helper.c			\
	stub.c

INCS=	cheribsdtest-helper.h cheribsdtest-helper-internal.h

LDFLAGS+=	-Wl,-T,${.CURDIR}/../../lib/libc_cheri/sandbox.ld \
		-nostdlib
MAN=

LIBADD=	md z c_cheri cheri_syscalls

NO_SHARED=	yes

.include <bsd.prog.mk>
