.if !target(__<${_this:T}>__)
__<${_this:T}>__:

ABI_P128=	yes

.if defined(P128_FORCED_GOT)
SHLIBDIR:=	/usr/lib128g
LIBDIR:=	/usr/lib128g
.else
SHLIBDIR:=	/usr/lib128
LIBDIR:=	/usr/lib128
.endif

.if defined(MACHINE_CPU)
MACHINE_CPU:=	${MACHINE_CPU:Ncheri:Nmorello}
.endif

MK_TESTS=	no

.endif
