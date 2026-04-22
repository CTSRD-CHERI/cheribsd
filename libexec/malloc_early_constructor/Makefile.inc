.include <src.opts.mk>

BINDIR=	/usr/libexec

.if ${.CURDIR:T:M*benchmark*}
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

PROG:=	${.PARSEDIR:tA:T}-${.CURDIR:T}
.PATH: ${.PARSEDIR}
SRCS:=	${.PARSEDIR:tA:T}.c
MAN=

.if ${.CURDIR:T:M*mt*}
LIBADD+=	pthread
.endif

.if !${.CURDIR:T:M*dynamic*} && !${.CURDIR:T:M*-c18n*}
NO_SHARED=t
.endif
