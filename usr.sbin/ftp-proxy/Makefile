.PATH:	${SRCTOP}/contrib/pf/ftp-proxy

PACKAGE=	pf
PROG=	ftp-proxy
MAN=	ftp-proxy.8

SRCS=	ftp-proxy.c filter.c

CFLAGS+=-I${SRCTOP}/contrib/pf/libevent
CFLAGS+= -I${SRCTOP}/lib/libpfctl -I${OBJTOP}/lib/libpfctl

LIBADD=	event1 pfctl

WARNS?=	3

# ld.lld: error: could not determine size of cap reloc against local object snl_f_p_empty
LD_FATAL_WARNINGS=	no

.include <bsd.prog.mk>
