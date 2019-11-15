#	$OpenBSD: Makefile,v 1.13 2014/05/12 19:11:19 espie Exp $
# $FreeBSD$

# -DEXTENDED 
# 	if you want the paste & spaste macros.

.include <src.opts.mk>

PROG=	m4
CFLAGS+=-DEXTENDED -I${.CURDIR} -I${SRCTOP}/lib/libopenbsd
LIBADD=	m openbsd

NO_WMISSING_VARIABLE_DECLARATIONS=

SRCS=	eval.c expr.c look.c main.c misc.c gnum4.c trace.c parser.y
.if target(bootstrap_m4_tokenizer)
# When crossbuilding on non-FreeBSD we need to first build m4 with pre-generated
# tokenizer files and the build the real m4 once we have lex+yacc.
# Avoid pulling in bsd.prog.mk early when this makefile is included from
# tools/build/bootstrap-m4/Makefile
SRCS+=	tokenizer.c
.else
SRCS+=	tokenizer.l
.endif

GENFILES=	tokenizer.c parser.c parser.h
WARNS=	3

tokenizer.o: parser.h

CLEANFILES+=	parser.c parser.h tokenizer.o tokenizer.c

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
