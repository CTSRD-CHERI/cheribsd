.PATH:	${SRCTOP}/contrib/pf/authpf

PACKAGE=pf
PROG=	authpf
MAN=	authpf.8
BINOWN=	root
BINGRP= authpf
BINMODE= 6555

SRCS=   authpf.c

# XXX ALTQ:
CFLAGS+= -DENABLE_ALTQ
CFLAGS+= -I${SRCTOP}/lib/libpfctl -I${OBJTOP}/lib/libpfctl

LIBADD=	m util pfctl

WARNS?=	3

LINKS=	${BINDIR}/authpf ${BINDIR}/authpf-noip
MLINKS=	authpf.8 authpf-noip.8

# ld.lld: error: could not determine size of cap reloc against local object snl_f_p_empty
LD_FATAL_WARNINGS=	no

.include <bsd.prog.mk>
