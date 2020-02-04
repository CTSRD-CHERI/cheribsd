# $FreeBSD$

# cleandir is run with the wrong context for libcompat so don't do
# anything in that case.
.if !make(cleandir)
.if !targets(__<${_this:T}>__)
__<${_this:T}>__:

.if defined(_LIBCOMPAT)
COMPAT_ARCH=	${TARGET_ARCH}
COMPAT_CPUTYPE=	${TARGET_CPUTYPE}
.if (defined(WANT_COMPILER_TYPE) && ${WANT_COMPILER_TYPE} == gcc) || \
    (defined(X_COMPILER_TYPE) && ${X_COMPILER_TYPE} == gcc)
COMPAT_COMPILER_TYPE=	gcc
.else
COMPAT_COMPILER_TYPE=	clang
.endif
.else
COMPAT_ARCH=	${MACHINE_ARCH}
COMPAT_CPUTYPE=	${CPUTYPE}
.include <bsd.compiler.mk>
COMPAT_COMPILER_TYPE=${COMPILER_TYPE}
.endif

# -------------------------------------------------------------------
# 32 bit world
.if ${COMPAT_ARCH} == "amd64"
HAS_COMPAT=32
.if empty(COMPAT_CPUTYPE)
LIB32CPUFLAGS=	-march=i686 -mmmx -msse -msse2
.else
LIB32CPUFLAGS=	-march=${COMPAT_CPUTYPE}
.endif
.if ${COMPAT_COMPILER_TYPE} == gcc
.else
LIB32CPUFLAGS+=	-target x86_64-unknown-freebsd13.0
.endif
LIB32CPUFLAGS+=	-m32
LIB32_MACHINE=	i386
LIB32_MACHINE_ARCH=	i386
LIB32WMAKEENV=	MACHINE_CPU="i686 mmx sse sse2"
LIB32WMAKEFLAGS=	\
		AS="${XAS} --32" \
		LD="${XLD} -m elf_i386_fbsd -L${WORLDTMP}/usr/lib32"

.elif ${COMPAT_ARCH} == "powerpc64"
HAS_COMPAT=32
.if empty(COMPAT_CPUTYPE)
LIB32CPUFLAGS=	-mcpu=powerpc
.else
LIB32CPUFLAGS=	-mcpu=${COMPAT_CPUTYPE}
.endif

.if ${COMPAT_COMPILER_TYPE} == "gcc"
LIB32CPUFLAGS+=	-m32
.else
LIB32CPUFLAGS+=	-target powerpc-unknown-freebsd13.0

# Use BFD to workaround ld.lld issues on PowerPC 32 bit 
LIB32CPUFLAGS+= -fuse-ld=${LD_BFD}
.endif

LIB32_MACHINE=	powerpc
LIB32_MACHINE_ARCH=	powerpc
LIB32WMAKEFLAGS=	\
		LD="${LD_BFD} -m elf32ppc_fbsd"

.elif ${COMPAT_ARCH:Mmips64*}
HAS_COMPAT=32
.if ${COMPAT_COMPILER_TYPE} == gcc
.if empty(COMPAT_CPUTYPE)
LIB32CPUFLAGS=	-march=mips3
.else
LIB32CPUFLAGS=	-march=${COMPAT_CPUTYPE}
.endif
.else
.if ${COMPAT_ARCH:Mmips64el*}
LIB32CPUFLAGS=  -target mipsel-unknown-freebsd13.0
.else
LIB32CPUFLAGS=  -target mips-unknown-freebsd13.0
.endif
.endif
LIB32CPUFLAGS+= -mabi=32
LIB32_MACHINE=	mips
.if ${COMPAT_ARCH:Mmips64el*}
LIB32_MACHINE_ARCH=	mipsel
_EMULATION=	elf32ltsmip_fbsd
.else
LIB32_MACHINE_ARCH=	mips
_EMULATION=	elf32btsmip_fbsd
.endif
LIB32WMAKEFLAGS= LD="${XLD} -m ${_EMULATION}"
LIB32LDFLAGS=	-Wl,-m${_EMULATION}
.endif

LIB32WMAKEFLAGS+= NM="${XNM}"
LIB32WMAKEFLAGS+= OBJCOPY="${XOBJCOPY}"

LIB32CFLAGS=	-DCOMPAT_32BIT
LIB32DTRACE=	${DTRACE} -32
LIB32WMAKEFLAGS+=	-DCOMPAT_32BIT

# -------------------------------------------------------------------
# 64 bit world
.if ${COMPAT_ARCH:Mmips64*c*}
HAS_COMPAT=64
# XXX: clang specific
.if ${COMPAT_ARCH:Mmips64el*}
LIB64CPUFLAGS=  -target mipsel-unknown-freebsd13.0
.else
LIB64CPUFLAGS=  -target cheri-unknown-freebsd13.0
.endif
LIB64CPUFLAGS+=	-mabi=64
LIB64_MACHINE=	mips
LIB64_MACHINE_ARCH=	mips64
.if ${COMPAT_ARCH:Mmips64el*}
_EMULATION=	elf64ltsmip_fbsd
.else
_EMULATION=	elf64btsmip_fbsd
.endif
LIB64WMAKEFLAGS= LD="${XLD} -m ${_EMULATION}"
LIB64LDFLAGS=	-Wl,-m${_EMULATION}
.endif

LIB64WMAKEFLAGS+= NM="${XNM}" OBJCOPY="${XOBJCOPY}"

LIB64CFLAGS=	-DCOMPAT_64BIT
LIB64DTRACE=	${DTRACE} -64
LIB64WMAKEFLAGS+=	-DCOMPAT_64BIT

# -------------------------------------------------------------------
# CHERI world
.if ${COMPAT_ARCH:Mmips64*} && !${COMPAT_ARCH:Mmips64*c*}
.if ${COMPAT_ARCH:Mmips*el*}
.error No little endian CHERI
.endif
HAS_COMPAT+=CHERI
LIBCHERICFLAGS=		-DCOMPAT_CHERI
LIBCHERICPUFLAGS=  -target cheri-unknown-freebsd13.0 -mabi=purecap
LIBCHERI_MACHINE=	mips
LIBCHERI_MACHINE_ARCH=	mips64c128
LIBCHERIWMAKEFLAGS=	LIBCHERI=yes
# Forward the cross linker and binutils
.for BINUTIL in ${XBINUTILS}
LIBCHERIWMAKEFLAGS+=	${BINUTIL}="${X${BINUTIL}}"
.endfor
.endif

# -------------------------------------------------------------------
# soft-fp world
.if ${COMPAT_ARCH:Marmv[67]*}
HAS_COMPAT=SOFT
LIBSOFTCFLAGS=        -DCOMPAT_SOFTFP
LIBSOFTCPUFLAGS= -mfloat-abi=softfp
LIBSOFT_MACHINE=	arm
LIBSOFT_MACHINE_ARCH=	${COMPAT_ARCH}
LIBSOFTWMAKEENV= CPUTYPE=soft
LIBSOFTWMAKEFLAGS=        -DCOMPAT_SOFTFP
.endif

# -------------------------------------------------------------------
# In the program linking case, select LIBCOMPAT
.if defined(NEED_COMPAT)
.ifndef HAS_COMPAT
.warning NEED_COMPAT defined, but no LIBCOMPAT is available (COMPAT_ARCH == ${COMPAT_ARCH}
.elif !${HAS_COMPAT:M${NEED_COMPAT}} && ${NEED_COMPAT} != "any"
.error NEED_COMPAT (${NEED_COMPAT}) defined, but not in HAS_COMPAT (${HAS_COMPAT})
.elif ${NEED_COMPAT} == "any"
.endif
.ifdef WANT_COMPAT
.error Both WANT_COMPAT and NEED_COMPAT defined
.endif
WANT_COMPAT:=	${NEED_COMPAT}
.endif

.if defined(HAS_COMPAT) && defined(WANT_COMPAT)
.if ${WANT_COMPAT} == "any"
_LIBCOMPAT:=	${HAS_COMPAT:[1]}
.else
_LIBCOMPAT:=	${WANT_COMPAT}
.endif
.endif

# -------------------------------------------------------------------
# Generic code for each type.
# Set defaults based on type.
libcompat=	${_LIBCOMPAT:tl}
_LIBCOMPAT_MAKEVARS=	_OBJTOP TMP CPUFLAGS CFLAGS CXXFLAGS LDFLAGS \
			_MACHINE _MACHINE_ARCH WMAKEENV WMAKEFLAGS WMAKE
.for _var in ${_LIBCOMPAT_MAKEVARS}
.if !empty(LIB${_LIBCOMPAT}${_var})
LIBCOMPAT${_var}?=	${LIB${_LIBCOMPAT}${_var}}
.endif
.endfor

# Shared flags
LIBCOMPAT_OBJTOP?=	${OBJTOP}/obj-lib${libcompat}

LIBCOMPATCFLAGS+=	${LIBCOMPATCPUFLAGS} \
			-L${WORLDTMP}/usr/lib${libcompat} \
			--sysroot=${WORLDTMP} \
			${BFLAGS}

LIBCOMPATWMAKEENV+=	MACHINE=${LIBCOMPAT_MACHINE}
LIBCOMPATWMAKEENV+=	MACHINE_ARCH=${LIBCOMPAT_MACHINE_ARCH}

# -B is needed to find /usr/lib32/crti.o for GCC and /usr/libsoft/crti.o for
# Clang/GCC.
LIBCOMPATCFLAGS+=	-B${WORLDTMP}/usr/lib${libcompat}

.if defined(WANT_COMPAT)
LIBDIR_BASE:=	/usr/lib${libcompat}
_LIB_OBJTOP=	${LIBCOMPAT_OBJTOP}
CFLAGS+=	${LIBCOMPATCFLAGS}
LDFLAGS+=	${CFLAGS} ${LIBCOMPATLDFLAGS}
MACHINE=	${LIBCOMPAT_MACHINE}
MACHINE_ARCH=	${LIBCOMPAT_MACHINE_ARCH}
.endif

.endif
.endif # !make(cleandir)
