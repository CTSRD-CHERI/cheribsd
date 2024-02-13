PROG_CXX=	cpg-reducer

MAN=

# graphics/graphviz isn't available for CheriABI.
MACHINE_ARCH=	aarch64
CXXFLAGS+=	-I/usr/local64/include
LDADD=		-lcgraph -lgvc
LDFLAGS=	-L/usr/local64/lib

.include <bsd.prog.mk>
