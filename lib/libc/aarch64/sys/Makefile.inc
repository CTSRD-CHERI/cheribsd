MIASM:=	${MIASM:Nfreebsd[467]_*}

SRCS+=	__vdso_gettc.c \
	sched_getcpu_gen.c

MDASM=	cerror.S \
	syscall.S

.ifndef RTLD_SANDBOX
MDASM+=	vfork.S
.endif
