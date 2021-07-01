# $FreeBSD$

.include <src.opts.mk>

.if ${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	64
.include <bsd.compat.mk>
.endif

TESTSDIR=	${TESTSBASE}/libexec/rtld-elf/cheri/abi-mismatch/dlopen-hybrid
ATF_TESTS_C+=dlopen-hybrid

.include <bsd.test.mk>
