# $FreeBSD$

# Use the following command to build local debug version of dynamic
# linker:
# make DEBUG_FLAGS=-g DEBUG=-DDEBUG WITHOUT_TESTS=yes all

.include <src.opts.mk>
MK_SSP=		no
MK_CHERI_SHARED_PROG:=yes

.PATH: ${.CURDIR}/../../lib/libmalloc_simple

# TODO: disable this once we believe RTLD works reliably
# Disable DEBUG to get a fair performance comparison to rtld-elf
# DEBUG=-DDEBUG
.ifdef RTLD_DEBUG_VERBOSE
CFLAGS+=-DDEBUG -DDEBUG_VERBOSE=${RTLD_DEBUG_VERBOSE}
.elif defined(BUILD_RTLD_DEBUG)
CFLAGS+=-DDEBUG
.endif

# Make per-file captable opt-in since it slows down normal code that doesn't
# use it and increases the size of plt stubs.
# This could be optimized to use different stubs for per-file stubs but for
# now making it opt-in is easier.
# TODO: add a make options for this (e.g. MK_BENCHMARK_OPTIONS)?
.ifdef RTLD_PER_FUNCTION_CAPTABLE_SUPPORT
CFLAGS+=-DRTLD_SUPPORT_PER_FUNCTION_CAPTABLE=1
.else
CFLAGS+=-DRTLD_SUPPORT_PER_FUNCTION_CAPTABLE=0
.endif


PROG?=		ld-cheri-elf.so.1
SRCS=		rtld_start.S reloc.c rtld.c heap.c malloc.c cheri_reloc.c
.PATH: ${.CURDIR}/../rtld-elf
SRCS+=	rtld_lock.c map_object.c xmalloc.c debug.c libmap.c

MAN=
NEED_CHERI=	pure
MK_CHERI_SHARED=yes
CSTD?=		gnu99
CFLAGS+=	-Wall -DFREEBSD_ELF -DIN_RTLD -ffreestanding
CFLAGS+=	-I${SRCTOP}/lib/csu/common \
		-I${SRCTOP}/lib/libc/${RTLD_ARCH}
.if exists(${.CURDIR}/${MACHINE_ARCH})
RTLD_ARCH=	${MACHINE_ARCH}
.else
RTLD_ARCH=	${MACHINE_CPUARCH}
.endif
CFLAGS+=	-I${.CURDIR}/${RTLD_ARCH} -I${.CURDIR} -I${.CURDIR}/../rtld-elf
LDFLAGS+=	-nostdlib -e rtld_start
NO_WCAST_ALIGN=	yes
WARNS?=		6
INSTALLFLAGS=	-C -b
CXXFLAGS+=-Wall -Wextra
PRECIOUSPROG=
BINDIR=		/libexec
#SYMLINKS=	${BINDIR}/${PROG} ${LIBEXECDIR}/${PROG}

CFLAGS+=	-fpic
CFLAGS+=	-DPIC $(DEBUG)
CFLAGS.reloc.c+=-fno-jump-tables

# Since we pass -shared, we shouldn't also pass -pie
# TODO: should we use -pie instead of -shared for rtld?
MK_PIE:=	no
LDFLAGS+=	-shared -Wl,-Bsymbolic -Wl,-z,defs
# avoid accidentally depending on non-existent symbols
LDFLAGS+=	-Wl,-no-undefined
LIBADD=		c_pic

# For floating-point functions used by gdtoa.
LIBADD+=	compiler_rt

# for the rtld_printf functions:
SIMPLE_PRINTF_PREFIX=rtld
.include "${SRCTOP}/lib/libsimple_printf/Makefile.inc"

.if ${MK_SYMVER} == "yes"
# LIBCSRCDIR does not appear to be set correctly for libcheribuildenv
LIBCSRCDIR=	${SRCTOP}/lib/libc
VERSION_DEF=	${LIBCSRCDIR}/Versions.def
SYMBOL_MAPS=	${.CURDIR}/../rtld-elf/Symbol.map
VERSION_MAP=	Version.map
LDFLAGS+=	-Wl,--version-script=${VERSION_MAP}

.if exists(${.CURDIR}/${RTLD_ARCH}/Symbol.map)
SYMBOL_MAPS+=	${.CURDIR}/${RTLD_ARCH}/Symbol.map
.endif
.endif

.sinclude "${.CURDIR}/${RTLD_ARCH}/Makefile.inc"

.PATH: ${.CURDIR}/${RTLD_ARCH} ${.CURDIR}/../rtld-elf/${RTLD_ARCH}


HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
${PROG_FULL}:	${VERSION_MAP}
.include <bsd.symver.mk>
#CFLAGS:=	${CFLAGS} -O0
