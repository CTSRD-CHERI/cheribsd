.include <src.opts.mk>

TESTSDIR=	${TESTSBASE}/libexec/rtld-elf/cheri/abi-mismatch

.if !${MACHINE_ABI:Mpurecap} || ${MK_LIB64} == "yes"
SUBDIR+=	basic_hybrid_lib
TESTS_SUBDIRS+=	dlopen-hybrid
.endif

.if ${MACHINE_ABI:Mpurecap} || ${MK_LIB64C} == "yes"
SUBDIR+=	basic_purecap_lib
TESTS_SUBDIRS+=	dlopen-purecap
.endif

#PLAIN_TESTS_C=				option-domain-search_test
#SRCS.option-domain-search_test=		alloc.c convert.c hash.c options.c \
#					tables.c fake.c option-domain-search.c
#CFLAGS.option-domain-search_test+=	-I${.CURDIR:H}
#LIBADD.option-domain-search_test=	util

.include <bsd.test.mk>
