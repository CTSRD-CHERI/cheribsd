# $FreeBSD$

.include <src.opts.mk>

SUBDIR+=	libpythagoras target

SUBDIR_DEPEND_target=	libpythagoras

ATF_TESTS_C=	ld_library_pathfds
ATF_TESTS_C+=	ld_preload_fds

.for t in ${ATF_TESTS_C}
SRCS.$t=	$t.c common.c
.endfor

WARNS?=		3

.if ${MACHINE_ABI:Mpurecap}
SUBDIR+=	cheri
.endif

.include <bsd.test.mk>
