
.PATH:	${SRCTOP}/contrib/pf/ftp-proxy

PACKAGE=	pf
PROG=	ftp-proxy
MAN=	ftp-proxy.8

SRCS=	ftp-proxy.c filter.c

CFLAGS+=-I${SRCTOP}/contrib/pf/libevent
CFLAGS+= -I${SRCTOP}/lib/libpfctl -I${OBJTOP}/lib/libpfctl

LIBADD=	event1 pfctl

# ld.lld: error: could not determine size of cap reloc against local object nla_p_donemsg
LD_FATAL_WARNINGS=no

WARNS?=	3

.include <bsd.prog.mk>
