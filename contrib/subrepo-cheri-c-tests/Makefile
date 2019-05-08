.SUFFIXES:
.SUFFIXES: .c .o .dump .s .ll

SDK_ROOT ?= ~/sdk/

TESTS=$(TESTS_CLANG_PURECAP) $(TESTS_CLANG_HYBRID) $(TESTS_LIBC)
TESTS_DIRS=$(TESTS_CLANG_HYBRID_DIR) $(TESTS_CLANG_PURECAP_DIR) $(TESTS_LIBC_DIR)
TESTS_CLANG_PURECAP_DIR=clang-purecap
TESTS_CLANG_HYBRID_DIR=clang-hybrid
TESTS_CLANG_PURECAP:=\
	clang_purecap_array\
	clang_purecap_atomic\
	clang_purecap_badcall\
	clang_purecap_capcmp\
	clang_purecap_capret\
	clang_purecap_capretaddr\
	clang_purecap_funptr\
	clang_purecap_init\
	clang_purecap_input\
	clang_purecap_int64math\
	clang_purecap_intcap\
	clang_purecap_null\
	clang_purecap_output\
	clang_purecap_smallint\
	clang_purecap_stack_cap\
	clang_purecap_uint64math\
	clang_purecap_uintcapmath\
	clang_purecap_union\
	clang_purecap_va_args\
	clang_purecap_va_copy\
	clang_purecap_va_die
TESTS_CLANG_HYBRID:=\
	clang_hybrid_bcopy\
	clang_hybrid_cast\
	clang_hybrid_cursor\
	clang_hybrid_cursor_trivial\
	clang_hybrid_intcap\
	clang_hybrid_load_data\
	clang_hybrid_memcpy\
	clang_hybrid_memmove\
	clang_hybrid_opaque\
	clang_hybrid_pack\
	clang_hybrid_store_data\
	clang_hybrid_struct\
	clang_hybrid_sub\
	clang_hybrid_toy
#	XXX-LPT: CHERI FP is not well tried, disable such tests for now\
	clang_hybrid_load_double\
	clang_hybrid_load_float\ #
$(info $(TESTS_CLANG_HYBRID))
TESTS_LIBC_DIR=libc
TESTS_LIBC:=\
	libc_malloc\
	libc_memcpy\
	libc_memmove\
	libc_printf\
	libc_qsort\
	libc_setjmp\
	libc_string

CFLAGS=-mcpu=mips4 -mabi=purecap -msoft-float -g -cheri-linker -Werror -O3 -target cheri-unknown-freebsd -Wall
CFLAGS+=-DHAVE_MALLOC_USUABLE_SIZE
CFLAGS+=-I.
CFLAGS_TESTS_CLANG_=$(CFLAGS:-mabi%=)
CFLAGS_TESTS_CLANG_HYBRID=-mabi=n64 $(CFLAGS_TESTS_CLANG_)
CFLAGS_TESTS_CLANG_PURECAP =-mabi=purecap $(CFLAGS_TESTS_CLANG_)

LDFLAGS=-cheri-linker -lc -lmalloc_simple
LDFLAGS_TESTS_CLANG_HYBRID=$(LDFLAGS:-lmalloc_simple=)

VPATH:=$(TESTS_DIRS)


all: $(TESTS_CLANG_PURECAP) $(TESTS_CLANG_HYBRID) $(TESTS_LIBC) run.sh

install: all
	cp ${TESTS} run.sh ${DESTDIR}/

%: %.c test_runtime.o Makefile
	${SDK_ROOT}/bin/clang test_runtime.o ${CFLAGS} ${LDFLAGS} $< -o $@

$(TESTS_CLANG_PURECAP): %: %.c test_runtime.o Makefile
	${SDK_ROOT}/bin/clang test_runtime.o $(CFLAGS_TESTS_CLANG_PURECAP) $(LDFLAGS) $< -o $@

$(TESTS_CLANG_HYBRID): %: %.c test_runtime.n64.o Makefile
	${SDK_ROOT}/bin/clang test_runtime.n64.o $(CFLAGS_TESTS_CLANG_HYBRID) $(LDFLAGS_TESTS_CLANG_HYBRID) $< -o $@

%.ll: %.c Makefile
	${SDK_ROOT}/bin/clang ${CFLAGS} -S $< -o $@ -emit-llvm

%.s: %.c Makefile
	${SDK_ROOT}/bin/clang ${CFLAGS} -S $< -o $@

%.dump: %
	${SDK_ROOT}/bin/llvm-objdump -triple cheri-unknown-freebsd -d $< > $@

test_runtime.o: test_runtime.c
	${SDK_ROOT}/bin/clang -c ${CFLAGS} $< -o $@

test_runtime.n64.o: test_runtime.c
	${SDK_ROOT}/bin/clang -c $(CFLAGS:purecap=n64) $< -o $@

run.sh: run.sh.in
	sed 's/{INCLUDE_TESTS}/${TESTS}/g' run.sh.in > run.sh

clean:
	rm -f ${TESTS} test_runtime.o test_runtime.n64.o run.sh


%: %.c

# inc64math.c, intcapmath.c, and uint64math.c include uintcapmath.c
int64math:	uintcapmath.c
intcapmath:	uintcapmath.c
uint64math:	uintcapmath.c
