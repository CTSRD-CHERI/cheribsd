.PATH:	${SRCTOP}/contrib/pf/tftp-proxy

PROG=	tftp-proxy
SRCS=	tftp-proxy.c filter.c
MAN=	tftp-proxy.8

CFLAGS+= -I${SRCTOP}/lib/libpfctl -I${OBJTOP}/lib/libpfctl
LIBADD= pfctl

WARNS?=	3

# ld.lld: error: could not determine size of cap reloc against local object snl_f_p_empty
LD_FATAL_WARNINGS=	no

.include <bsd.prog.mk>
