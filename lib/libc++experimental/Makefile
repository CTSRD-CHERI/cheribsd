# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	clibs
.if ${MK_CHERI} != "no"
WANT_CHERI?=	hybrid
SRCDIR=		${SRCTOP}/contrib/subrepo-cheri-libc++
.else
SRCDIR=		${SRCTOP}/contrib/subrepo-cheri-libc++
.endif

LIB=		c++experimental
NO_PIC=
MK_PROFILE=	no

.PATH:		${SRCDIR}/src/experimental

SRCS+=		memory_resource.cpp

WARNS?=		0
CXXFLAGS+=	${PICFLAG}
CXXFLAGS+=	-isystem ${SRCDIR}/include
CXXFLAGS+=	-nostdinc++
CXXFLAGS+=	-nostdlib
CXXFLAGS+=	-D_LIBCPP_BUILDING_LIBRARY
CXXFLAGS+=	-DLIBCXXRT
CXXSTD?=	c++14

.include <bsd.lib.mk>
