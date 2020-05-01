#	$NetBSD: Makefile.inc,v 1.27 2005/10/07 17:16:40 tsutsui Exp $
# $FreeBSD$

SRCS+=	infinity.c fabs.c ldexp.c flt_rounds.c

# SRCS+=	flt_rounds.c fpgetmask.c fpgetround.c fpgetsticky.c fpsetmask.c \
#	fpsetround.c fpsetsticky.c

SRCS+=	_ctx_start.S _set_tp.c makecontext.c \
	signalcontext.c sigsetjmp.S \
	trivial-getcontextx.c

.if ${MACHINE_ABI:Mpurecap}
SRCS+=	_setjmp_c.S setjmp_c.S
.else
SRCS+=	_setjmp.S setjmp.S
.endif

# XXX: The reason those two are here and not in lib/libc/sys/Makefile.inc
#      is that it fails to link (missing _setjmp and _longjmp) otherwise.
.if ${MK_CHERI} == "yes"
SRCS+=	coaccept.c cocall.c
.endif
