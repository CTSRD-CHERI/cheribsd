# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	helloworld_cxx

MAN=
NEED_CHERI=	pure

CXXFLAGS+=	-std=c++11

# Always build shared
MK_CHERI_SHARED_PROG=yes

.include <bsd.prog.mk>
