.include <bsd.own.mk>

NEED_CHERI=	pure
LDFLAGS+=	-nodefaultlibs -nostdlib -nostartfiles -Wl,-rpath,'$$$$ORIGIN'
TESTSDIR=	${TESTSBASE}/libexec/rtld-cheri-elf/plt
WARNS=		6
