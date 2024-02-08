
.PATH:	${SRCTOP}/contrib/pf/tftp-proxy

PROG=	tftp-proxy
SRCS=	tftp-proxy.c filter.c
MAN=	tftp-proxy.8

CFLAGS+= -I${SRCTOP}/lib/libpfctl -I${OBJTOP}/lib/libpfctl
LIBADD= pfctl

# ld.lld: error: could not determine size of cap reloc against local object nla_p_donemsg
LD_FATAL_WARNINGS=no

WARNS?=	3

.include <bsd.prog.mk>
