MIASM:=	${MIASM:Nfreebsd[467]_*}

SRCS+=	__vdso_gettc.c \
	sched_getcpu_gen.c

MDASM=	cerror.S \
	syscall.S \
	vfork.S

.ifdef RTLD_SANDBOX
SRCS+=	thr_exit.c
PSEUDO+=	_thr_exit.o
.endif
