# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	clibs
.if ${MK_CHERI} != "no"
WANT_CHERI?=	hybrid
SRCDIR=		${SRCTOP}/contrib/subrepo-cheri-libcxxrt/src
.else
SRCDIR=		${SRCTOP}/contrib/subrepo-cheri-libcxxrt/src
.endif
SHLIB_MAJOR=	1
SHLIBDIR?=	/lib
ALLOW_MIPS_SHARED_TEXTREL=

.PATH: ${SRCDIR}

LIB=		cxxrt

SRCS+=		libelftc_dem_gnu3.c\
		terminate.cc\
		dynamic_cast.cc\
		memory.cc\
		auxhelper.cc\
		exception.cc\
		stdexcept.cc\
		typeinfo.cc\
		guard.cc

WARNS=		0
CFLAGS+=	-isystem ${SRCDIR} -nostdinc++
CXXSTD?=	c++14
VERSION_MAP=	${.CURDIR}/Version.map

.include <bsd.lib.mk>
