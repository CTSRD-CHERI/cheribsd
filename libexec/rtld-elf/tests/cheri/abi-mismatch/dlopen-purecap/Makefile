# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=	64C
.include <bsd.compat.mk>
.endif

TESTSDIR=	${TESTSBASE}/libexec/rtld-elf/cheri/abi-mismatch/dlopen-purecap
ATF_TESTS_C+=dlopen-purecap

.include <bsd.test.mk>
