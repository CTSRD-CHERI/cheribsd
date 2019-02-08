# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	helloworld_cxx

MAN=
NEED_CHERI=	pure

CXXFLAGS+=	-std=c++11

.if ${MK_CHERI_SHARED} == "yes"
# Always build shared if we're building shared libs.
MK_CHERI_SHARED_PROG=yes
.endif

.include <bsd.prog.mk>
