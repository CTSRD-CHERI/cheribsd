# $FreeBSD$

.include <src.opts.mk>

TESTSDIR=	${TESTSBASE}/libexec/rtld-cheri-elf/abi-mismatch

# Disable when building a pure-cap world as we don't support
# bsd.cheri.mk hacks there. Alternative workaround needed.
# Similarly, non-MIPS lacks bsd.cheri.mk, even for hybrid.
# We should probably use bsd.compat.mk to get either freebsd64
# or cheriabi and allow forcing nocheri or hybrid for freebsd64.
.if !${MACHINE_ABI:Mpurecap} && ${MACHINE_CPUARCH} == "mips"
SUBDIR+=	basic_nocheri_lib basic_hybrid_lib basic_purecap_lib
.endif

#PLAIN_TESTS_C=				option-domain-search_test
#SRCS.option-domain-search_test=		alloc.c convert.c hash.c options.c \
#					tables.c fake.c option-domain-search.c
#CFLAGS.option-domain-search_test+=	-I${.CURDIR:H}
#LIBADD.option-domain-search_test=	util

.if !${MACHINE_ABI:Mpurecap}
TESTS_SUBDIRS+=	dlopen-hybrid
.endif
TESTS_SUBDIRS+=	dlopen-purecap

.include <bsd.test.mk>
