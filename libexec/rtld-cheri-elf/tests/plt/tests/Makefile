# $FreeBSD$

# TESTSDIR=	${TESTSBASE}/libexec/rtld-cheri-elf/plt

PLAIN_TESTS_C=	test_write \
	load_global_int_call \
	load_global_int_fnptr_call \
	load_global_int_data_ref \
	test_library_cgp \
	test_library_cgp_asm

SRCS.test_library_cgp_asm= test_library_cgp_asm.S

SRCS.load_global_int_fnptr_call=load_global_int_fnptr_call.c external_fnptr.c

#CFLAGS.option-domain-search_test+=	-I${.CURDIR:H}
#LIBADD.option-domain-search_test=	util

LDFLAGS+=	-L${.OBJDIR}/../libtest_rtld_plt
CFLAGS+=	-I${.CURDIR}/../libtest_rtld_plt
DPADD+=		${.OBJDIR}/../libtest_rtld_plt/libtest_rtld_plt.so.0
LDADD=		-ltest_rtld_plt

.include <bsd.test.mk>
# This needs to be done after bsd.cheri.mk (so that it works even if we pass
# CHERI_USE_CAP_TABLE on the make command line)
CFLAGS:=	${CFLAGS:N-cheri-cap-table-abi=*} -cheri-cap-table-abi=plt
