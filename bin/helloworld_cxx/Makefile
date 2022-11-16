# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	64C
.include <bsd.compat.mk>
.endif

PROG_CXX=	helloworld_cxx

MAN=
CXXFLAGS+=	-std=c++11

.include <bsd.prog.mk>
