
.include <src.opts.mk>

PACKAGE=	pkg-bootstrap

CONFS=		CheriBSD.conf
.if ${MACHINE_ABI:Mpurecap} && !defined(PKG_SUFFIX)
# Install a configuration file for a pkg repository with debug packages for use
# with the default package manager only if the world is compiled for CheriABI.
CONFS+=		CheriBSD-debug.conf
.endif
CONFSDIR=	/etc/pkg${PKG_SUFFIX}
CONFSMODE=	644
PROG?=	pkg${PKG_SUFFIX}
SRCS=	pkg.c dns_utils.c config.c hash.c
MAN?=	pkg${PKG_SUFFIX}.7

CFLAGS+='-DPKG_SUFFIX="${PKG_SUFFIX}"'

CFLAGS+=-I${SRCTOP}/contrib/libucl/include
.PATH:	${SRCTOP}/contrib/libucl/include
LIBADD=	archive fetch ucl crypto ssl util md

.include <bsd.prog.mk>
