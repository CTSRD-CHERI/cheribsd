# $FreeBSD$

# cleandir is run with the wrong context for libcompat so don't do
# anything in that case.
.if !make(cleandir)
.if !targets(__<${_this:T}>__)
__<${_this:T}>__:

.include <src.opts.mk>

.if defined(_LIBCOMPAT)
COMPAT_ARCH?=	${TARGET_ARCH}
COMPAT_CPUTYPE?= ${CPUTYPE_${_LIBCOMPAT}}
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
.if ${MK_LIB32} != "no"
.if ${COMPAT_ARCH} == "amd64"
HAS_COMPAT=32
.if empty(COMPAT_CPUTYPE)
LIB32CPUFLAGS=	-march=i686 -mmmx -msse -msse2
.else
LIB32CPUFLAGS=	-march=${COMPAT_CPUTYPE}
.endif
.if ${COMPAT_COMPILER_TYPE} == gcc
.else
LIB32CPUFLAGS+=	-target x86_64-unknown-freebsd${OS_REVISION}
.endif
LIB32CPUFLAGS+=	-m32
LIB32_MACHINE=	i386
LIB32_MACHINE_ARCH=	i386
LIB32WMAKEENV=	MACHINE_CPU="i686 mmx sse sse2"
LIB32WMAKEFLAGS=	\
		AS="${XAS} --32" \
		LD="${XLD} -m elf_i386_fbsd"

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
LIB32CPUFLAGS+=	-target powerpc-unknown-freebsd${OS_REVISION}
.endif

LIB32_MACHINE=	powerpc
LIB32_MACHINE_ARCH=	powerpc
LIB32WMAKEFLAGS=	\
		LD="${XLD} -m elf32ppc_fbsd"
.endif

LIB32WMAKEFLAGS+= NM="${XNM}"
LIB32WMAKEFLAGS+= OBJCOPY="${XOBJCOPY}"

LIB32CFLAGS=	-DCOMPAT_32BIT
LIB32DTRACE=	${DTRACE} -32
LIB32WMAKEFLAGS+=	-DCOMPAT_32BIT
LIB32_MACHINE_ABI=	${MACHINE_ABI:N*64:Nptr*:Npurecap} long32 ptr32
.if ${COMPAT_ARCH} == "amd64"
LIB32_MACHINE_ABI+=	time32
.else
LIB32_MACHINE_ABI+=	time64
.endif
.endif # ${MK_LIB32} != "no"

# -------------------------------------------------------------------
# 64 bit world
.if ${MK_LIB64} != "no"
.if ${COMPAT_ARCH:Maarch64*c*}
HAS_COMPAT=64
LIB64_MACHINE=	arm64
LIB64_MACHINE_ARCH=aarch64
LIB64WMAKEENV=	MACHINE_CPU="arm64 cheri"
LIB64WMAKEFLAGS= LD="${XLD}" CPUTYPE=morello
# XXX: clang specific
LIB64CPUFLAGS=	-target aarch64-unknown-freebsd13.0
LIB64CPUFLAGS+=	-march=morello -mabi=aapcs
.endif

.if ${COMPAT_ARCH:Mriscv*c*}
HAS_COMPAT=64
COMPAT_RISCV_ABI=	lp64
.if !${COMPAT_ARCH:Mriscv*sf}
COMPAT_RISCV_ABI:=	${COMPAT_RISCV_ABI}d
.endif
LIB64_MACHINE=	riscv
LIB64_MACHINE_ARCH=riscv64
LIB64WMAKEENV=	MACHINE_CPU="riscv cheri"
LIB64WMAKEFLAGS= LD="${XLD}" CPUTYPE=cheri
# XXX: clang specific
LIB64CPUFLAGS=	-target riscv64-unknown-freebsd13.0
LIB64CPUFLAGS+=	-march=${COMPAT_RISCV_MARCH} -mabi=${COMPAT_RISCV_ABI}
.endif

LIB64WMAKEFLAGS+= NM="${XNM}" OBJCOPY="${XOBJCOPY}"

LIB64CFLAGS=	-DCOMPAT_64BIT
LIB64DTRACE=	${DTRACE} -64
LIB64WMAKEFLAGS+=	-DCOMPAT_64BIT
LIB64_MACHINE_ABI=	${MACHINE_ABI:Npurecap:Nptr*} ptr64
.endif # ${MK_LIB64} != "no"

# -------------------------------------------------------------------
# CHERI world
.if ${MK_LIB64C} != "no"
.if ${COMPAT_ARCH} == "aarch64"
HAS_COMPAT+=64C
LIB64C_MACHINE=	arm64
LIB64C_MACHINE_ARCH=	aarch64c
LIB64CCPUFLAGS=	-target aarch64-unknown-freebsd13.0
LIB64CCPUFLAGS+=	-march=morello+c64 -mabi=purecap
.elif ${COMPAT_ARCH:Mriscv64*} && !${COMPAT_ARCH:Mriscv64*c*}
HAS_COMPAT+=64C
LIB64C_MACHINE=	riscv
LIB64C_MACHINE_ARCH=	${COMPAT_ARCH}c
LIB64CWMAKEFLAGS=	CPUTYPE=cheri
LIB64CCPUFLAGS=	-target riscv64-unknown-freebsd13.0
COMPAT_RISCV_ABI=	l64pc128
.if !${MACHINE_ARCH:Mriscv*sf}
COMPAT_RISCV_ABI:=	${COMPAT_RISCV_ABI}d
.endif
LIB64CCPUFLAGS+=	-march=${COMPAT_RISCV_MARCH} -mabi=${COMPAT_RISCV_ABI}
.endif	# ${COMPAT_ARCH:Mriscv64*}
.endif # ${MK_LIB64C} != "no"

.if ${COMPAT_ARCH:Mriscv*}
# See bsd.cpu.mk
COMPAT_RISCV_MARCH=	rv64ima
.if !${COMPAT_ARCH:Mriscv*sf*}
COMPAT_RISCV_MARCH:=	${COMPAT_RISCV_MARCH}fd
.endif
COMPAT_RISCV_MARCH:=	${COMPAT_RISCV_MARCH}c
.if ${COMPAT_ARCH:Mriscv*c*} || (defined(HAS_COMPAT) && ${HAS_COMPAT:M64C})
COMPAT_RISCV_MARCH:=	${COMPAT_RISCV_MARCH}xcheri
.endif
.endif

# Common CHERI flags
.if defined(HAS_COMPAT) && ${HAS_COMPAT:M64C}
LIB64CCFLAGS+=	-DCOMPAT_CHERI
LIB64CWMAKEFLAGS+=	COMPAT_CHERI=yes
LIB64C_MACHINE_ABI=	${MACHINE_ABI:Nptr*} purecap ptr128c

# This duplicates some logic in bsd.cpu.mk that is needed for the
# WANT_COMPAT/NEED_COMPAT case.
LIB64CCFLAGS+=	-D__LP64__=1

LIB64CCFLAGS+=	-Werror=implicit-function-declaration

.ifdef CHERI_USE_CAP_TABLE
LIB64CCFLAGS+=	-cheri-cap-table-abi=${CHERI_USE_CAP_TABLE}
.endif

.if defined(CHERI_SUBOBJECT_BOUNDS)
# Allow per-subdirectory overrides if we know that there is maximum that works
.if defined(CHERI_SUBOBJECT_BOUNDS_MAX)
LIB64CCFLAGS+=	-Xclang -cheri-bounds=${CHERI_SUBOBJECT_BOUNDS_MAX}
.else
LIB64CCFLAGS+=	-Xclang -cheri-bounds=${CHERI_SUBOBJECT_BOUNDS}
.endif # CHERI_SUBOBJECT_BOUNDS_MAX
CHERI_SUBOBJECT_BOUNDS_DEBUG?=yes
.if ${CHERI_SUBOBJECT_BOUNDS_DEBUG} == "yes"
# If debugging is enabled, clear SW permission bit 2 when the bounds are reduced
LIB64CCFLAGS+=	-mllvm -cheri-subobject-bounds-clear-swperm=2
.endif # CHERI_SUBOBJECT_BOUNDS_DEBUG
.endif # CHERI_SUBOBJECT_BOUNDS
.endif

# -------------------------------------------------------------------
# In the program linking case, select LIBCOMPAT
.if defined(NEED_COMPAT)
.ifndef HAS_COMPAT
.warning NEED_COMPAT defined, but no LIBCOMPAT is available (COMPAT_ARCH == ${COMPAT_ARCH})
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
.elif !${HAS_COMPAT:M${WANT_COMPAT}}
.warning WANT_COMPAT (${WANT_COMPAT}) defined, but not in HAS_COMPAT (${HAS_COMPAT})
.undef WANT_COMPAT
.else
_LIBCOMPAT:=	${WANT_COMPAT}
.endif
.else # defined(HAS_COMPAT) && defined(WANT_COMPAT)
.undef WANT_COMPAT
.endif

# -------------------------------------------------------------------
# Generic code for each type.
# Set defaults based on type.
libcompat=	${_LIBCOMPAT:tl}
_LIBCOMPAT_MAKEVARS=	_OBJTOP TMP CPUFLAGS CFLAGS CXXFLAGS LDFLAGS \
			_MACHINE _MACHINE_ARCH _MACHINE_ABI \
			WMAKEENV WMAKEFLAGS WMAKE WORLDTMP
.for _var in ${_LIBCOMPAT_MAKEVARS}
.if !empty(LIB${_LIBCOMPAT}${_var})
LIBCOMPAT${_var}?=	${LIB${_LIBCOMPAT}${_var}}
.endif
.endfor

WORLDTMP?=		${SYSROOT}

# Shared flags
LIBCOMPAT_OBJTOP?=	${OBJTOP}/obj-lib${libcompat}

LIBCOMPATCFLAGS+=	${LIBCOMPATCPUFLAGS} \
			--sysroot=${WORLDTMP} \
			${BFLAGS}

LIBCOMPATLDFLAGS+=	-L${WORLDTMP}/usr/lib${libcompat}

LIBCOMPATWMAKEENV+=	MACHINE=${LIBCOMPAT_MACHINE}
LIBCOMPATWMAKEENV+=	MACHINE_ARCH=${LIBCOMPAT_MACHINE_ARCH}
# Note: TARGET and TARGET_ARCH must be set on the command line to override
# previous assignments
LIBCOMPATWMAKEFLAGS+=	TARGET=${LIBCOMPAT_MACHINE}
LIBCOMPATWMAKEFLAGS+=	TARGET_ARCH=${LIBCOMPAT_MACHINE_ARCH}
# Forward the cross linker and binutils
.for BINUTIL in ${XBINUTILS}
LIBCOMPATWMAKEENV+=	${BINUTIL}="${X${BINUTIL}}"
.endfor

# -B is needed to find /usr/lib32/crti.o for gcc.
LIBCOMPATCFLAGS+=	-B${WORLDTMP}/usr/lib${libcompat}

.if defined(WANT_COMPAT)
LIBDIR_BASE:=	/usr/lib${libcompat}
_LIB_OBJTOP=	${LIBCOMPAT_OBJTOP}
CFLAGS+=	${LIBCOMPATCFLAGS}
LDFLAGS+=	${CFLAGS} ${LIBCOMPATLDFLAGS}
MACHINE:=	${LIBCOMPAT_MACHINE}
MACHINE_ARCH:=	${LIBCOMPAT_MACHINE_ARCH}
MACHINE_ABI:=	${LIBCOMPAT_MACHINE_ABI}
.endif

.endif
.endif # !make(cleandir)
