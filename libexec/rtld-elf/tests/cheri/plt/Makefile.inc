.include <bsd.own.mk>

NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
LDFLAGS+=	-nodefaultlibs -nostdlib -nostartfiles -Wl,-rpath,'$$$$ORIGIN'
TESTSDIR=	${TESTSBASE}/libexec/rtld-cheri-elf/plt
WARNS=		6
