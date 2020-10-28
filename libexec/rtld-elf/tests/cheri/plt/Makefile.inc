# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.endif

.include <bsd.own.mk>

LDFLAGS+=	-nodefaultlibs -nostdlib -nostartfiles -Wl,-rpath,'$$$$ORIGIN'
TESTSDIR=	${TESTSBASE}/libexec/rtld-elf/cheri/plt
WARNS=		6
