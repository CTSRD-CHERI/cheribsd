# $FreeBSD$

NEED_COMPAT=	CHERI
.include <bsd.compat.mk>
.include <src.opts.mk>

PROG_CXX=	helloworld_cxx

MAN=
CXXFLAGS+=	-std=c++11

# Note: this makefile might be included from bin/Makefile even if the
# COMPAT_CHERI value for MK_CXX == "no" due to src.opts.mk limitations.
.if ${MK_CXX} != "no"
.include <bsd.prog.mk>
.else
all install:
	@echo "Not building ${PROG_CXX} since MK_CXX=${MK_CXX}"
.endif
