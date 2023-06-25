#	@(#)Makefile	8.2 (Berkeley) 4/18/94
# $FreeBSD$

.include <src.opts.mk>

PROG=	arp
MAN=	arp.4 arp.8


SRCS=	arp.c

.if ${MK_NETLINK_SUPPORT} != "no"
SRCS+=	arp_netlink.c

# ld.lld: error: could not determine size of cap reloc against local object nla_p_donemsg
LD_FATAL_WARNINGS=no
.else
CFLAGS+=-DWITHOUT_NETLINK
.endif

LIBADD=	xo

WARNS?=	3

.include <bsd.prog.mk>
