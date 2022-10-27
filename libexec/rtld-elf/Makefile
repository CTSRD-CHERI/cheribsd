# $FreeBSD$

# Use the following command to build local debug version of dynamic
# linker:
# make DEBUG_FLAGS=-g WITHOUT_TESTS=yes all

RTLD_ELF_DIR:=	${.PARSEDIR}

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

.include <src.opts.mk>
PACKAGE=	clibs
MK_PIE=		no # Always position independent using local rules
# Not compatible with sanitizer instrumentation or SSP.
MK_ASAN=	no
MK_SSP=		no
MK_UBSAN=	no

.ifdef RTLD_SANDBOX
CFLAGS+=-DRTLD_SANDBOX
.endif

.if !defined(NEED_COMPAT) && !defined(RTLD_SANDBOX)
CONFS=		libmap.conf
.endif
PROG?=		ld-elf.so.1
.if (${PROG:M*ld-elf32*} != "")
TAGS+=		lib32
.endif
.if (${PROG:M*ld-elf64*} != "")
TAGS+=		lib64
.endif
.PATH: ${RTLD_ELF_DIR}
SRCS= \
	crtbrand.S \
	rtld_start.S \
	reloc.c \
	rtld.c \
	rtld_lock.c \
	map_object.c \
	xmalloc.c \
	debug.c \
	libmap.c
.if !${MACHINE_ABI:Mpurecap}
SRCS+= \
	rtld_malloc.c \
	rtld_printf.c
.endif
MAN?=		rtld.1
ACFLAGS+=	-DLOCORE
CFLAGS+=	-Wall -DFREEBSD_ELF -DIN_RTLD -ffreestanding
CFLAGS+=	-I${SRCTOP}/lib/csu/common
.if exists(${RTLD_ELF_DIR}/${MACHINE_ARCH:S/powerpc64le/powerpc64/})
RTLD_ARCH=	${MACHINE_ARCH:S/powerpc64le/powerpc64/}
.else
RTLD_ARCH=	${MACHINE_CPUARCH}
.endif
CFLAGS+=	-I${RTLD_ELF_DIR}/${RTLD_ARCH} -I${RTLD_ELF_DIR}

NO_WCAST_ALIGN=	yes
INSTALLFLAGS=	-C -b
PRECIOUSPROG=
BINDIR=		/libexec
SYMLINKS=	../..${BINDIR}/${PROG} ${LIBEXECDIR}/${PROG}
MLINKS?=	rtld.1 ld-elf.so.1.1 \
		rtld.1 ld.so.1

CFLAGS+=	-fpic -DPIC $(DEBUG)
# Since we pass -shared, we shouldn't also pass -pie
MK_PIE:=	no

LDFLAGS+=	-shared -Wl,-Bsymbolic -Wl,-z,defs -nostdlib -e ${RTLD_ENTRY}
# Pull in the dependencies that we use from libc
.include "rtld-libc/Makefile.inc"
.if ${MK_TOOLCHAIN} == "no"
LDFLAGS+=	-L${LIBCDIR}
.endif

VERSION_DEF=	${LIBCSRCDIR}/Versions.def
SYMBOL_MAPS=	${RTLD_ELF_DIR}/Symbol.map
VERSION_MAP=	Version.map
LDFLAGS+=	-Wl,--version-script=${VERSION_MAP}

.if exists(${RTLD_ELF_DIR}/${RTLD_ARCH}/Symbol.map)
SYMBOL_MAPS+=	${RTLD_ELF_DIR}/${RTLD_ARCH}/Symbol.map
.endif

.ifdef RTLD_SANDBOX
SYMBOL_MAPS+=	${RTLD_ELF_DIR}/Symbol-c18n.map
.endif

.sinclude "${RTLD_ELF_DIR}/${RTLD_ARCH}/Makefile.inc"
RTLD_ENTRY?=	.rtld_start

# Since moving rtld-elf to /libexec, we need to create a symlink.
# Fixup the existing binary that's there so we can symlink over it.
beforeinstall:
.if exists(${DESTDIR}/usr/libexec/${PROG}) && ${MK_STAGING} == "no"
	-chflags -h noschg ${DESTDIR}/usr/libexec/${PROG}
.endif

.PATH: ${RTLD_ELF_DIR}/${RTLD_ARCH} ${SRCTOP}/lib/csu/common

.if ${MACHINE_CPU:Mcheri}
.PATH: ${RTLD_ELF_DIR}/cheri
SRCS+=		cheri_reloc.c
CFLAGS+=	-I${RTLD_ELF_DIR}/cheri
.endif

.if ${MACHINE_ABI:Mpurecap}
.PATH: ${SRCTOP}/lib/libmalloc_simple
SRCS+=		heap.c malloc.c

CFLAGS+=	-I${SRCTOP}/lib/libc/${RTLD_ARCH}
CXXFLAGS+=	-Wall -Wextra

SIMPLE_PRINTF_PREFIX=rtld
.include "${SRCTOP}/lib/libsimple_printf/Makefile.inc"
.endif

.if ${.CURDIR} == ${RTLD_ELF_DIR}
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.endif

# Some of the required math functions (div & mod) are implemented in
# libcompiler_rt on some architectures.
LIBADD+=	compiler_rt

.include <bsd.prog.mk>
${PROG_FULL}:	${VERSION_MAP}
.include <bsd.symver.mk>

.if ${COMPILER_TYPE} == "gcc"
# GCC warns about redeclarations even though they have __exported
# and are therefore not identical to the ones from the system headers.
CFLAGS+=	-Wno-redundant-decls
.endif
