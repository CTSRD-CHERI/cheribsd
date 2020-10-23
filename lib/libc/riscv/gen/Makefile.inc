# $FreeBSD$

SRCS+=	_ctx_start.S \
	fabs.S \
	flt_rounds.c \
	infinity.c \
	ldexp.c \
	makecontext.c \
	_setjmp.S \
	_set_tp.c \
	setjmp.S \
	sigsetjmp.S \
	trivial-getcontextx.c

# XXX: The reason those two are here and not in lib/libc/sys/Makefile.inc
#      is that it fails to link (missing _setjmp and _longjmp) otherwise.
.if ${MK_CHERI} == "yes"
SRCS+=	coaccept.c cocall.c
.endif
