# $FreeBSD$

.include <src.opts.mk>

PROG?=	cheritest
SRCS=	cheritest.c

SRCS+=	cheritest_bounds_globals.c					\
	cheritest_bounds_globals_x.c					\
	cheritest_bounds_heap.c						\
	cheritest_bounds_stack.c					\
	cheritest_fault.c						\
	cheritest_kbounce.c						\
	cheritest_longjmp.c						\
	cheritest_registers.c						\
	cheritest_sandbox.S						\
	cheritest_sealcap.c						\
	cheritest_signal.c						\
	cheritest_string.c						\
	cheritest_syscall.c						\
	cheritest_tls.c							\
	cheritest_util.c						\
	cheritest_vm.c							\
	cheritest_vm_swap.c						\
	cheritest_zlib.c
# This test is broken
CFLAGS.cheritest_vm_swap.c+=-Wno-cheri-capability-misuse

CHERITEST_DIR:=	${.PARSEDIR}

.ifdef CHERIABI_TESTS
SRCS+=	cheritest_cheriabi.c
SRCS+=	cheritest_cheriabi_open.c
CFLAGS+=	-DCHERIABI_TESTS
.endif

.PATH: ${SRCTOP}/sys/mips/cheri
SRCS+=	cheri_memcpy_c.S
CFLAGS.cheri_memcpy_c.S=-D__KERN_FUNC_PREFIX -D_KERNEL -DINVARIANTS
CFLAGS+=	-DKERNEL_MEMCPY_TESTS

.ifdef CHERI_C_TESTS
CHERI_C_TESTS_DIR=	${SRCTOP}/contrib/subrepo-cheri-c-tests
.if exists(${CHERI_C_TESTS_DIR}/Makefile)
.PATH: ${CHERI_C_TESTS_DIR} \
		${CHERI_C_TESTS_DIR}/clang-hybrid \
		${CHERI_C_TESTS_DIR}/clang-purecap \
		${CHERI_C_TESTS_DIR}/libc
CFLAGS+=	-DCHERI_C_TESTS \
		-I${CHERI_C_TESTS_DIR}

CFLAGS+=	-DTEST_CUSTOM_FRAMEWORK -I${CHERITEST_DIR} \
		-DHAVE_MALLOC_USUABLE_SIZE
TEST_SRCS!=	grep ^DECLARE_TEST ${CHERI_C_TESTS_DIR}/cheri_c_testdecls.h | \
		    sed -e 's/.*(\([^,]*\),.*/\1.c/'
SRCS+=	test_runtime.c	\
	${TEST_SRCS}

# These tests do math with (u)intcap_t's where the provenance (or
# rather lack there of) isn't clear to the compiler.
CFLAGS.clang_purecap_intcapmath.c+=	-Wno-cheri-provenance -Wno-unknown-warning-option
CFLAGS.clang_purecap_uintcapmath.c+=	-Wno-cheri-provenance -Wno-unknown-warning-option

.for test in ${TEST_SRCS}
# Avoid the need for extern declarations for variables/functions that are
# declared global so that the compiler emits them
CFLAGS.${test}+=-Wno-missing-prototypes -Wno-missing-variable-declarations
.endfor
.endif
.endif

.ifdef CHERITHREAD_TESTS
CFLAGS+=	-DCHERITHREAD_TESTS
.endif

MAN=

.if ${PROG:Mcheritest*}
NEED_CHERI=	hybrid
.elif ${PROG:Mcheriabitest*}
WANT_CHERI=	pure
.else
.error Unknown cheritest variant ${PROG}
.endif
LIBADD= 	z

LIBADD+=	xo util

.ifdef CHERI_DYNAMIC_TESTS
CFLAGS+=	-DCHERI_DYNAMIC_TESTS
.else
NO_SHARED?=	YES
# XXX-JC: Enable unconditionally once we have a dynamic libcheri
.if ${MK_LIBCHERI} == "yes"
CFLAGS+=	-DCHERI_LIBCHERI_TESTS
LIBADD+=	cheri
SRCS+=		cheritest_ccall.c					\
		cheritest_fd.c						\
		cheritest_libcheri.c					\
		cheritest_libcheri_cxx.cc				\
		cheritest_libcheri_fault.c				\
		cheritest_libcheri_local.c				\
		cheritest_libcheri_trustedstack.c			\
		cheritest_libcheri_var.c
.endif
.endif

.ifdef CHERITHREAD_TESTS
LIBADD+=	pthread
SRCS+=		cheritest_tls_threads.c
# XXX-JC: Enable unconditionally once we have a dynamic libcheri
.ifndef CHERI_DYNAMIC_TESTS
.if ${MK_LIBCHERI} == "yes"
SRCS+=		cheritest_libcheri_pthreads.c
.endif
.endif
.endif

.include <bsd.prog.mk>
