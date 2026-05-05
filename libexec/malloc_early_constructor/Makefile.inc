.include <src.opts.mk>

BINDIR=	/usr/libexec

VARIANT=		${.CURDIR:T}
VARIANT_SUFFICES=	${VARIANT:S/-/ /g}

.if ${VARIANT_SUFFICES:Mbenchmark}
.if !${MACHINE_ABI:Mbenchmark}
NEED_COMPAT=	64CB
.include <bsd.compat.mk>
.endif
.else
.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=    64C
.include <bsd.compat.mk>
.endif
.endif

PROG:=	${.PARSEDIR:tA:T}-${VARIANT}
.PATH: ${.PARSEDIR}
SRCS:=	${.PARSEDIR:tA:T}.c
MAN=

.if ${VARIANT_SUFFICES:Mmt}
LIBADD+=	pthread
.endif

.if !${VARIANT_SUFFICES:Mdynamic} && !${VARIANT_SUFFICES:Mc18n}
NO_SHARED=t
.endif
