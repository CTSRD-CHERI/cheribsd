# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	pkg-bootstrap

PKGCONF?=	CheriBSD.conf
CONFS=		${PKGCONF}
CONFSNAME_${PKGCONF}=	${PKGCONF:C/\.conf.+$/.conf/}
CONFSDIR=	/etc/pkg${PKG_SUFFIX}
CONFSMODE=	644
PROG?=	pkg${PKG_SUFFIX}
SRCS=	pkg.c dns_utils.c config.c
MAN?=	pkg${PKG_SUFFIX}.7

CFLAGS+='-DPKG_SUFFIX="${PKG_SUFFIX}"'

CFLAGS+=-I${SRCTOP}/contrib/libucl/include
.PATH:	${SRCTOP}/contrib/libucl/include
LIBADD=	archive fetch ucl crypto ssl util

.include <bsd.prog.mk>
