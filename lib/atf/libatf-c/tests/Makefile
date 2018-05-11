# $FreeBSD$

.include <bsd.init.mk>

PACKAGE=	tests

TESTS_SUBDIRS=	detail

ATF=		${SRCTOP}/contrib/atf
.PATH:		${ATF}/atf-c
.PATH:		${ATF}/atf-c/detail

CFLAGS+=	-DATF_INCLUDEDIR='"${INCLUDEDIR}"'
CFLAGS+=	-I${ATF}

# macros_test.c contains a double 'const const' which will be gone with
# the import of atf-0.18.
# TODO(jmmv): Remove this workaround once we do that update.
CFLAGS.clang+=	-Wno-duplicate-decl-specifier

${PACKAGE}FILES+=	macros_h_test.c
${PACKAGE}FILES+=	unused_test.c

.for _T in	build_test \
		error_test \
		tc_test \
		tp_test \
		utils_test
ATF_TESTS_C+=	${_T}
SRCS.${_T}=	${_T}.c test_helpers.c
.endfor

.if ${CC} == "cc
# These tests are broken when using a cross toolchain (they embed ${CC}
# and try to compile with it).
.for _T in	atf_c_test \
		check_test \
		macros_test
ATF_TESTS_C+=	${_T}
SRCS.${_T}=	${_T}.c test_helpers.c
.endfor
.endif

.include <bsd.test.mk>
