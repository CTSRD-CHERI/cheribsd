.include <bsd.p128.mk>

.include <src.opts.mk>

.if ${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	64
.include <bsd.compat.mk>
.endif

PROG=	ld-elf128.so.1
MAN=
MLINKS=	rtld.1 ld-elf128.so.1.1

.PATH:  ${SRCTOP}/libexec/rtld-elf
.include "${SRCTOP}/libexec/rtld-elf/Makefile"
