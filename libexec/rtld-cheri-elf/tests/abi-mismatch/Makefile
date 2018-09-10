# $FreeBSD$

TESTSDIR=	${TESTSBASE}/libexec/rtld-cheri-elf/abi-mismatch

SUBDIR+=	basic_nocheri_lib basic_hybrid_lib basic_purecap_lib \
		wrong_size_purecap_lib wrong_size_hybrid_lib

#PLAIN_TESTS_C=				option-domain-search_test
#SRCS.option-domain-search_test=		alloc.c convert.c hash.c options.c \
#					tables.c fake.c option-domain-search.c
#CFLAGS.option-domain-search_test+=	-I${.CURDIR:H}
#LIBADD.option-domain-search_test=	util

TESTS_SUBDIRS+=	dlopen-hybrid dlopen-purecap

.include <bsd.test.mk>
