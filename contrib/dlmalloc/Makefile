SDKBIN?=/home/bed22/git/llvm-project-cheri/Build/bin
SDKROOT?=/home/bed22/bsdtools/cheribsd-root/cheribsd128
CC=${SDKBIN}/clang -target cheri-unknown-freebsd --sysroot=${SDKROOT}
LD=${CC} -fuse-ld=lld -B ${SDKBIN}
DEBUG?=1

CFLAGS=-Wall -Werror
CFLAGS+=-mabi=purecap -msoft-float
CFLAGS+=-std=c11
CFLAGS+=-Wno-error=unused-function

CFLAGS+=-DCAPREVOKE -DCHERI_SET_BOUNDS
LDFLAGS+=-lcheri_caprevoke

CFLAGS+=-DSAFE_FREEBUF

ifeq ($(DEBUG),1)
CFLAGS+=-O0
CFLAGS+=-ggdb
CFLAGS+=-DDEBUG=1 -DABORT_ON_ASSERT_FAILURE=1 -DVERBOSE=1
else # DEBUG
CFLAGS+=-O3
CFLAGS+=-g0
CFLAGS+=-fomit-frame-pointer
CFLAGS+=-fno-stack-protector
CFLAGS+=-DINSECURE=1

ifneq (,$(findstring clang,$(CC)))
ifneq (,$(findstring lld,$(LD)))
# Use link-time optimizations if clang/lld.
CFLAGS+=-flto
LDFLAGS+=-O3
LDFLAGS+=--lto-O3
endif
endif

endif # DEBUG

ifeq ($(DEBUG),1)
libdlmalloc_nonreuse.so: dlmalloc_nonreuse.o
	$(LD) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^
else
libdlmalloc_nonreuse.so: dlmalloc_nonreuse.o
	$(LD) $(CFLAGS) $(LDFLAGS) -shared $^ -o $@
	strip $@
endif

dlmalloc_nonreuse.o: dlmalloc_nonreuse.c dlmalloc_nonreuse.h
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

dlmalloc_nonreuse-dlprefix.o: dlmalloc_nonreuse.c dlmalloc_nonreuse.h
	$(CC) $(CFLAGS) -DUSE_DL_PREFIX -c $< -o $@

dlmalloc_test.o: dlmalloc_test.c
	$(CC) $(CFLAGS) -DUSE_DL_PREFIX -c $< -o $@

dlmalloc_test: dlmalloc_nonreuse-dlprefix.o dlmalloc_test.o
	$(LD) $(CFLAGS) $(LDFLAGS) -static dlmalloc_nonreuse-dlprefix.o dlmalloc_test.o -o $@

clean:
	rm -f dlmalloc_test *.o *.so
