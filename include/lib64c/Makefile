# purecap headers installed on hybrid

.include <src.opts.mk>

.if ${MK_CHERI_CAPREVOKE} != "no"
.PATH: ${SRCTOP}/lib/libcheri_caprevoke

INCS+=	libcaprevoke.h
INCSDIR_libcaprevoke.h=	${INCLUDEDIR}/cheri
.endif

.include <bsd.prog.mk>
