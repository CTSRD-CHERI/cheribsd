
# cleandir is run with the wrong context for libcompat so don't do
# anything in that case.
.if !make(cleandir)
.if !targets(__<${_this:T}>__)
__<${_this:T}>__:

.include <src.opts.mk>

.include <bsd.compat.pre.mk>

.if defined(_LIBCOMPATS)
COMPAT_ARCH?=	${TARGET_ARCH}
.for _LIBCOMPAT in ${_ALL_LIBCOMPATS}
LIB${_LIBCOMPAT}CPUTYPE?=	${CPUTYPE_${_LIBCOMPAT}}
.endfor
.if (defined(WANT_COMPILER_TYPE) && ${WANT_COMPILER_TYPE} == gcc) || \
    (defined(X_COMPILER_TYPE) && ${X_COMPILER_TYPE} == gcc)
COMPAT_COMPILER_TYPE=	gcc
.else
COMPAT_COMPILER_TYPE=	clang
.endif
.else
COMPAT_ARCH=	${MACHINE_ARCH}
.for _LIBCOMPAT in ${_ALL_LIBCOMPATS}
LIB${_LIBCOMPAT}CPUTYPE=	${CPUTYPE}
.endfor
.endif

# -------------------------------------------------------------------
# 32 bit world
.if ${MK_LIB32} != "no"
.if ${COMPAT_ARCH} == "amd64"
HAS_COMPAT+=	32
.if empty(LIB32CPUTYPE)
LIB32CPUFLAGS=	-march=i686 -mmmx -msse -msse2
.else
LIB32CPUFLAGS=	-march=${LIB32CPUTYPE}
.endif
LIB32CPUFLAGS.clang+=	-target x86_64-unknown-freebsd${OS_REVISION}
LIB32CPUFLAGS+=	-m32
LIB32_MACHINE=	i386
LIB32_MACHINE_ARCH=	i386
LIB32WMAKEENV=	MACHINE_CPU="i686 mmx sse sse2"
LIB32WMAKEFLAGS=	\
		LD="${XLD} -m elf_i386_fbsd"

.elif ${COMPAT_ARCH} == "powerpc64"
HAS_COMPAT+=	32
.if empty(LIB32CPUTYPE)
LIB32CPUFLAGS=	-mcpu=powerpc
.else
LIB32CPUFLAGS=	-mcpu=${LIB32CPUTYPE}
.endif

LIB32CPUFLAGS.gcc+=	-m32
LIB32CPUFLAGS.clang+=	-target powerpc-unknown-freebsd${OS_REVISION}

LIB32_MACHINE=	powerpc
LIB32_MACHINE_ARCH=	powerpc
LIB32WMAKEFLAGS=	\
		LD="${XLD} -m elf32ppc_fbsd"

.elif ${COMPAT_ARCH:Maarch64*}
HAS_COMPAT+=	32
.if empty(LIB32CPUTYPE) || ${LIB32CPUTYPE} == "morello"
LIB32CPUFLAGS=	-march=armv7
.else
LIB32CPUFLAGS=	-mcpu=${LIB32CPUTYPE}
.endif
.if ${COMPAT_ARCH:Maarch64*c*}
LIB32CPUFLAGS+=	-mabi=aapcs
.endif

LIB32CPUFLAGS+=	-m32
LIB32CPUFLAGS.clang+=	-target armv7-unknown-freebsd${OS_REVISION}-gnueabihf

LIB32_MACHINE=	arm
LIB32_MACHINE_ARCH=	armv7
LIB32WMAKEFLAGS=	\
		LD="${XLD} -m armelf_fbsd"
.endif

.if ${MACHINE_ABI:Mpurecap}
LIB32CPUFLAGS+=	-U__LP64__
.endif

LIB32WMAKEFLAGS+= NM="${XNM}"
LIB32WMAKEFLAGS+= OBJCOPY="${XOBJCOPY}"

LIB32DTRACE=	${DTRACE} -32
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
HAS_COMPAT+=	64
LIB64_MACHINE=	arm64
LIB64_MACHINE_ARCH=aarch64
LIB64WMAKEENV=	MACHINE_CPU="arm64 cheri"
LIB64WMAKEFLAGS= LD="${XLD}" CPUTYPE=morello
# XXX: clang specific
LIB64CPUFLAGS=	-target aarch64-unknown-freebsd13.0
LIB64CPUFLAGS+=	-march=morello -mabi=aapcs
.endif

.if ${COMPAT_ARCH:Mriscv*c*}
HAS_COMPAT+=	64
LIB64_RISCV_ABI=	lp64
.if !${COMPAT_ARCH:Mriscv*sf}
LIB64_RISCV_ABI:=	${LIB64_RISCV_ABI}d
.endif
LIB64_MACHINE=	riscv
LIB64_MACHINE_ARCH=riscv64
LIB64WMAKEENV=	MACHINE_CPU="riscv cheri"
LIB64WMAKEFLAGS= LD="${XLD}" CPUTYPE=cheri
# XXX: clang specific
LIB64CPUFLAGS=	-target riscv64-unknown-freebsd13.0
LIB64CPUFLAGS+=	-march=${LIB64_RISCV_MARCH} -mabi=${LIB64_RISCV_ABI}
.endif

LIB64WMAKEFLAGS+= NM="${XNM}" OBJCOPY="${XOBJCOPY}"

LIB64DTRACE=	${DTRACE} -64
LIB64_MACHINE_ABI=	${MACHINE_ABI:Npurecap:Nptr*} ptr64
.endif # ${MK_LIB64} != "no"

# -------------------------------------------------------------------
# CHERI world
.if ${MK_LIB64C} != "no"
.if ${COMPAT_ARCH} == "aarch64"
HAS_COMPAT+=	64C
LIB64C_MACHINE=	arm64
LIB64C_MACHINE_ARCH=	aarch64c
LIB64CCPUFLAGS=	-target aarch64-unknown-freebsd13.0
LIB64CCPUFLAGS+=	-march=morello -mabi=purecap
.elif ${COMPAT_ARCH:Mriscv64*} && !${COMPAT_ARCH:Mriscv64*c*}
HAS_COMPAT+=	64C
LIB64C_MACHINE=	riscv
LIB64C_MACHINE_ARCH=	${COMPAT_ARCH}c
LIB64CWMAKEFLAGS=	CPUTYPE=cheri
LIB64CCPUFLAGS=	-target riscv64-unknown-freebsd13.0
LIB64C_RISCV_ABI=	l64pc128
.if !${MACHINE_ARCH:Mriscv*sf}
LIB64C_RISCV_ABI:=	${LIB64C_RISCV_ABI}d
.endif
LIB64CCPUFLAGS+=	-march=${LIB64C_RISCV_MARCH} -mabi=${LIB64C_RISCV_ABI}
.endif	# ${COMPAT_ARCH:Mriscv64*}
.endif # ${MK_LIB64C} != "no"

.if ${COMPAT_ARCH:Mriscv*}
.for _LIBCOMPAT in ${HAS_COMPAT}
# See bsd.cpu.mk
LIB${_LIBCOMPAT}_RISCV_MARCH=	rv64ima
.if !${COMPAT_ARCH:Mriscv*sf*}
LIB${_LIBCOMPAT}_RISCV_MARCH:=	${LIB${_LIBCOMPAT}_RISCV_MARCH}fd
.endif
LIB${_LIBCOMPAT}_RISCV_MARCH:=	${LIB${_LIBCOMPAT}_RISCV_MARCH}c
.if ${COMPAT_ARCH:Mriscv*c*} || ${_LIBCOMPAT:M64C}
LIB${_LIBCOMPAT}_RISCV_MARCH:=	${LIB${_LIBCOMPAT}_RISCV_MARCH}xcheri
.endif
.endfor
.endif

# Common CHERI flags
.if defined(HAS_COMPAT) && ${HAS_COMPAT:M64C}
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
# CHERI benchmarking world
.if ${MK_LIB64CB} != "no"
.if ${COMPAT_ARCH:Maarch64*}
HAS_COMPAT+=	64CB
LIB64CB_MACHINE=	arm64
LIB64CB_MACHINE_ARCH=aarch64cb
LIB64CBCPUFLAGS=	-target aarch64-unknown-freebsd13.0
LIB64CBCPUFLAGS+=	-march=morello -mabi=purecap-benchmark
LIB64CB_MACHINE_ABI=	${MACHINE_ABI:Nptr*:Npurecap} purecap ptr128c benchmark

# This duplicates some logic in bsd.cpu.mk that is needed for the
# WANT_COMPAT/NEED_COMPAT case.
LIB64CBCFLAGS+=	-D__LP64__=1

LIB64CBCFLAGS+=	-Werror=implicit-function-declaration

.ifdef CHERI_USE_CAP_TABLE
LIB64CBCFLAGS+=	-cheri-cap-table-abi=${CHERI_USE_CAP_TABLE}
.endif

.if defined(CHERI_SUBOBJECT_BOUNDS)
# Allow per-subdirectory overrides if we know that there is maximum that works
.if defined(CHERI_SUBOBJECT_BOUNDS_MAX)
LIB64CBCFLAGS+=	-Xclang -cheri-bounds=${CHERI_SUBOBJECT_BOUNDS_MAX}
.else
LIB64CBCFLAGS+=	-Xclang -cheri-bounds=${CHERI_SUBOBJECT_BOUNDS}
.endif # CHERI_SUBOBJECT_BOUNDS_MAX
CHERI_SUBOBJECT_BOUNDS_DEBUG?=yes
.if ${CHERI_SUBOBJECT_BOUNDS_DEBUG} == "yes"
# If debugging is enabled, clear SW permission bit 2 when the bounds are reduced
LIB64CBCFLAGS+=	-mllvm -cheri-subobject-bounds-clear-swperm=2
.endif # CHERI_SUBOBJECT_BOUNDS_DEBUG
.endif # CHERI_SUBOBJECT_BOUNDS
.endif # ${COMPAT_ARCH:Maarch64*}
.endif # ${MK_LIB64CB} != "no"

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
USE_COMPAT:=	${HAS_COMPAT:[1]}
.elif !${HAS_COMPAT:M${WANT_COMPAT}}
.warning WANT_COMPAT (${WANT_COMPAT}) defined, but not in HAS_COMPAT (${HAS_COMPAT})
.undef WANT_COMPAT
.else
USE_COMPAT:=	${WANT_COMPAT}
.endif

_LIBCOMPATS=	${USE_COMPAT}
.else # defined(HAS_COMPAT) && defined(WANT_COMPAT)
.undef WANT_COMPAT
.endif

libcompats=	${_LIBCOMPATS:tl}

# Update MACHINE and MACHINE_ARCH so they can be used in bsd.opts.mk via
# bsd.compiler.mk
.if defined(USE_COMPAT)
_LIBCOMPAT_MAKEVARS=	_MACHINE _MACHINE_ARCH _MACHINE_ABI
.for _var in ${_LIBCOMPAT_MAKEVARS}
.if !empty(LIB${USE_COMPAT}${_var})
LIBCOMPAT${_var}?=	${LIB${USE_COMPAT}${_var}}
.endif
.endfor

MACHINE:=	${LIBCOMPAT_MACHINE}
MACHINE_ARCH:=	${LIBCOMPAT_MACHINE_ARCH}
MACHINE_ABI:=	${LIBCOMPAT_MACHINE_ABI}
.endif

.if !defined(COMPAT_COMPILER_TYPE)
.include <bsd.compiler.mk>
COMPAT_COMPILER_TYPE=${COMPILER_TYPE}
.endif

# -------------------------------------------------------------------
# Generic code for each type.
# Set defaults based on type.
.for _LIBCOMPAT _libcompat in ${_LIBCOMPATS:@v@${v} ${v:tl}@}
WORLDTMP?=		${SYSROOT}

# Shared flags
LIB${_LIBCOMPAT}_OBJTOP?=	${OBJTOP}/obj-lib${_libcompat}

LIB${_LIBCOMPAT}CFLAGS+=	${LIB${_LIBCOMPAT}CPUFLAGS} \
				${LIB${_LIBCOMPAT}CPUFLAGS.${COMPAT_COMPILER_TYPE}} \
				-DCOMPAT_LIBCOMPAT=\"${_LIBCOMPAT}\" \
				-DCOMPAT_libcompat=\"${_libcompat}\" \
				-DCOMPAT_LIB${_LIBCOMPAT} \
				--sysroot=${WORLDTMP} \
				${BFLAGS}

LIB${_LIBCOMPAT}LDFLAGS+=	-L${WORLDTMP}/usr/lib${_libcompat}

LIB${_LIBCOMPAT}WMAKEFLAGS+=	COMPAT_LIBCOMPAT=${_LIBCOMPAT} \
				COMPAT_libcompat=${_libcompat}

LIB${_LIBCOMPAT}WMAKEENV+=	MACHINE=${LIB${_LIBCOMPAT}_MACHINE}
LIB${_LIBCOMPAT}WMAKEENV+=	MACHINE_ARCH=${LIB${_LIBCOMPAT}_MACHINE_ARCH}
# Note: TARGET and TARGET_ARCH must be set on the command line to override
# previous assignments
LIB${_LIBCOMPAT}WMAKEFLAGS+=	TARGET=${LIB${_LIBCOMPAT}_MACHINE}
LIB${_LIBCOMPAT}WMAKEFLAGS+=	TARGET_ARCH=${LIB${_LIBCOMPAT}_MACHINE_ARCH}
# Forward the cross linker and binutils
.for BINUTIL in ${XBINUTILS}
LIB${_LIBCOMPAT}WMAKEENV+=	${BINUTIL}="${X${BINUTIL}}"
.endfor

# -B is needed to find /usr/lib32/crti.o for gcc.
LIB${_LIBCOMPAT}CFLAGS+=	-B${WORLDTMP}/usr/lib${_libcompat}
.endfor

.if defined(USE_COMPAT)
LIB${USE_COMPAT}CPUFLAGS+= ${LIB${USE_COMPAT}CPUFLAGS.${COMPAT_COMPILER_TYPE}}

libcompat=	${USE_COMPAT:tl}

_LIBCOMPAT_MAKEVARS=	_OBJTOP TMP CPUFLAGS CFLAGS CXXFLAGS LDFLAGS \
			WMAKEENV WMAKEFLAGS WMAKE WORLDTMP
.for _var in ${_LIBCOMPAT_MAKEVARS}
.if !empty(LIB${USE_COMPAT}${_var})
LIBCOMPAT${_var}?=	${LIB${USE_COMPAT}${_var}}
.endif
.endfor

LIBDIR_BASE:=	/usr/lib${libcompat}
LIBDATADIR:=	/usr/lib${libcompat}
_LIB_OBJTOP=	${LIBCOMPAT_OBJTOP}
CFLAGS+=	${LIBCOMPATCFLAGS}
LDFLAGS+=	${CFLAGS} ${LIBCOMPATLDFLAGS}
.endif

.endif
.endif # !make(cleandir)
