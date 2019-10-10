# $FreeBSD$

# Use the following command to build local debug version of dynamic
# linker:
# make DEBUG_FLAGS=-g DEBUG=-DDEBUG WITHOUT_TESTS=yes all

.include <src.opts.mk>
MK_SSP=		no

RTLD_CHERI_ELF_DIR=${SRCTOP}/libexec/rtld-cheri-elf
RTLD_ELF_DIR=${SRCTOP}/libexec/rtld-elf

.PATH: ${RTLD_CHERI_ELF_DIR}/../../lib/libmalloc_simple

# Disable DEBUG to get a fair performance comparison to rtld-elf
# DEBUG=-DDEBUG
.ifdef BUILD_RTLD_DEBUG
.ifdef RTLD_DEBUG_VERBOSE
DEBUG+=-DDEBUG -DDEBUG_VERBOSE=${RTLD_DEBUG_VERBOSE}
.else
DEBUG+=-DDEBUG
.endif
.endif

.if empty(DEBUG) && !defined(RTLD_INCLUDE_DEBUG_MESSAGES)
# Avoid the overhead of all the debug checks now that we have a rtld-debug that
# can be used instead.
CFLAGS+=-DNO_LD_DEBUG
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

.if ${MACHINE_ARCH:Mmips*c*}
PROG?=		ld-elf.so.1
.else
PROG?=		ld-cheri-elf.so.1
.endif
.if ${MACHINE_ARCH:Mmips*c*} && ${PROG} == ld-elf.so.1
LINKS=		${BINDIR}/ld-elf.so.1 ${BINDIR}/ld-cheri-elf.so.1
.endif
SRCS=		rtld_start.S reloc.c rtld.c heap.c malloc.c cheri_reloc.c
.PATH: ${RTLD_ELF_DIR}
SRCS+=	rtld_lock.c map_object.c xmalloc.c debug.c libmap.c

MAN=
NEED_CHERI=	pure
CSTD?=		gnu99
CFLAGS+=	-Wall -DFREEBSD_ELF -DIN_RTLD -ffreestanding
.if !${MACHINE_ARCH:Mmips64*c*}
CFLAGS+=	-DCOMPAT_CHERI
.endif
CFLAGS+=	-I${SRCTOP}/lib/csu/common \
		-I${SRCTOP}/lib/libc/${RTLD_ARCH}
.if exists(${RTLD_CHERI_ELF_DIR}/${MACHINE_ARCH})
RTLD_ARCH=	${MACHINE_ARCH}
.else
RTLD_ARCH=	${MACHINE_CPUARCH}
.endif
CFLAGS+=	-I${RTLD_CHERI_ELF_DIR}/${RTLD_ARCH} -I${RTLD_CHERI_ELF_DIR} -I${RTLD_ELF_DIR}
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

# Add all the dependencies from libc:
BUILDING_RTLD_CHERI_ELF=yes
.include "${SRCTOP}/libexec/rtld-elf/rtld-libc/Makefile.inc"

# for the rtld_printf functions:
SIMPLE_PRINTF_PREFIX=rtld
.include "${SRCTOP}/lib/libsimple_printf/Makefile.inc"

.if ${MK_SYMVER} == "yes"
# LIBCSRCDIR does not appear to be set correctly for libcheribuildenv
LIBCSRCDIR=	${SRCTOP}/lib/libc
VERSION_DEF=	${LIBCSRCDIR}/Versions.def
SYMBOL_MAPS=	${RTLD_ELF_DIR}/Symbol.map
VERSION_MAP=	Version.map
LDFLAGS+=	-Wl,--version-script=${VERSION_MAP}

.if exists(${RTLD_CHERI_ELF_DIR}/${RTLD_ARCH}/Symbol.map)
SYMBOL_MAPS+=	${RTLD_CHERI_ELF_DIR}/${RTLD_ARCH}/Symbol.map
.endif
.endif

.sinclude "${RTLD_CHERI_ELF_DIR}/${RTLD_ARCH}/Makefile.inc"

.PATH: ${RTLD_CHERI_ELF_DIR}/${RTLD_ARCH} ${RTLD_ELF_DIR}/${RTLD_ARCH}

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
${PROG_FULL}:	${VERSION_MAP}
.include <bsd.symver.mk>
#CFLAGS:=	${CFLAGS} -O0
