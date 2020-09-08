# $FreeBSD$

.include <src.opts.mk>

SUBDIR+=	libpythagoras target

SUBDIR_DEPEND_target=	libpythagoras
ATF_TESTS_C=	ld_library_pathfds
WARNS?=		3

.if ${MACHINE_ABI:Mpurecap}
SUBDIR+=	cheri
.endif

.include <bsd.test.mk>
