#-
# Copyright (c) 2015, 2016 (SRI International)
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

.if defined(__BSD_PROG_MK)
.if ${MK_CHERI_PURE} == "yes" && !defined(TESTSDIR)
WANT_CHERI?=	pure
.endif
.endif

.if (${MACHINE_ARCH:Mmips64*} && ! ${MACHINE_ARCH:Mmips*c*}) || \
    defined(LIBCHERI)
.if !${.TARGETS:Mbuild-tools} && !defined(BOOTSTRAPPING)
.if defined(NEED_CHERI)
.if ${MK_CHERI} == "no"
.error NEED_CHERI defined, but CHERI is not enabled
.endif
.if ${NEED_CHERI} != "hybrid" && ${NEED_CHERI} != "pure" && ${NEED_CHERI} != "sandbox"
.error NEED_CHERI must be 'hybrid', 'pure', or 'sandbox'
.endif
WANT_CHERI:= ${NEED_CHERI}
.endif

.if defined(LIB_CXX) || defined(PROG_CXX) || defined(SHLIB_CXX)
.if ${MK_CHERI} != "no"
# We need to use CHERI clang for C++ because we no longer build libstdc++
WANT_CHERI?=	hybrid
# XXXAR: leave this for a while until everyone has updated clang to
# a version that defaults to libc++
LDFLAGS+=	-stdlib=libc++
.endif

.endif

.if ${MK_CHERI} != "no" && (!defined(WANT_CHERI) || ${WANT_CHERI} == "none" || ${WANT_CHERI} == "variables")
# When building MIPS code for CHERI ensure 16/32 byte stack alignment
# for libraries because it could also be used by hybrid code
# Note: libc sets WANT_CHERI=variables when building for MIPS so we also need to
# handle that case.
# TODO: should be only for libraries and not programs
.if ${COMPILER_TYPE} == "clang"
# GCC doesn't support -mstack-alignment but I think it has been patched
# to use 32 bytes anyway
.if ${MK_CHERI256} == "yes"
CFLAGS+=	-mstack-alignment=32
.else
CFLAGS+=	-mstack-alignment=16
.endif
.endif # $COMPILER_TYPE == clang
.endif # MIPS, not hybrid (adjust stack alignment)

.if ${MK_CHERI} != "no" && defined(WANT_CHERI) && ${WANT_CHERI} != "none"
_CHERI_COMMON_FLAGS=	-integrated-as --target=cheri-unknown-freebsd \
			-msoft-float \
			-cheri-uintcap=${CHERI_UINTCAP_MODE:Uoffset}
.ifdef WANT_AFL_FUZZ
# Build binaries static when fuzzing
.if defined(__BSD_PROG_MK)
NO_SHARED=yes
.endif
_CHERI_CC=		AFL_PATH=${CC:H}/../afl/usr/local/lib/afl/ ${CC:H}/../afl/usr/local/bin/afl-clang-fast ${_CHERI_COMMON_FLAGS}
_CHERI_CXX=		AFL_PATH=${CC:H}/../afl/usr/local/lib/afl/ ${CXX:H}/../afl/usr/local/bin/afl-clang-fast++ ${_CHERI_COMMON_FLAGS}
.else
_CHERI_CC=		${CC} ${_CHERI_COMMON_FLAGS}
_CHERI_CXX=		${CXX} ${_CHERI_COMMON_FLAGS}
.endif
_CHERI_CPP=		${CPP} ${_CHERI_COMMON_FLAGS}

.if defined(CHERI_SUBOBJECT_BOUNDS)
# Allow per-subdirectory overrides if we know that there is maximum that works
.if defined(CHERI_SUBOBJECT_BOUNDS_MAX)
_CHERI_COMMON_FLAGS+=	-Xclang -cheri-bounds=${CHERI_SUBOBJECT_BOUNDS_MAX}
.else
_CHERI_COMMON_FLAGS+=	-Xclang -cheri-bounds=${CHERI_SUBOBJECT_BOUNDS}
.endif # CHERI_SUBOBJECT_BOUNDS_MAX
CHERI_SUBOBJECT_BOUNDS_DEBUG?=yes
.if ${CHERI_SUBOBJECT_BOUNDS_DEBUG} == "yes"
# If debugging is enabled, clear SW permission bit 2 when the bounds are reduced
_CHERI_COMMON_FLAGS+=	-mllvm -cheri-subobject-bounds-clear-swperm=2
.endif # CHERI_SUBOBJECT_BOUNDS_DEBUG
.endif # CHERI_SUBOBJECT_BOUNDS

.if defined(SYSROOT)
_CHERI_COMMON_FLAGS+=	--sysroot=${SYSROOT}
.endif

.if ${WANT_CHERI} == "pure" || ${WANT_CHERI} == "sandbox"
MIPS_ABI:=	purecap
_CHERI_COMMON_FLAGS+=	-fpic
# Don't override libdir for tests since that causes the dlopen tests to fail
.if !defined(LIBDIR) || ${LIBDIR:S/^${TESTSBASE}//} == ${LIBDIR}
LIBDIR_BASE:=	/usr/libcheri
.else
.info "Not overriding LIBDIR for CHERI since ${.CURDIR} is a test library"
.endif
ROOTOBJDIR=	${OBJTOP}/obj-libcheri
.ifdef CHERI_USE_CAP_TABLE
CFLAGS+=	-cheri-cap-table-abi=${CHERI_USE_CAP_TABLE}
.endif
.ifdef CHERI_USE_CAP_TLS
CFLAGS+=	-cheri-cap-tls-abi=${CHERI_USE_CAP_TLS}
.endif
STATIC_CFLAGS+=	-ftls-model=local-exec

.ifdef NO_WERROR
# Implicit function declarations should always be an error in purecap mode as
# we will probably generate wrong code for calling them
CFLAGS+=-Werror=implicit-function-declaration
.endif
# Clang no longer defines __LP64__ for Cheri purecap ABI but there are a
# lot of files that use it to check for not 32-bit
# XXXAR: Remove this once we have checked all the #ifdef __LP64__ uses
CFLAGS+=	-D__LP64__=1
LDFLAGS+=	-Wl,-melf64btsmip_cheri_fbsd
.if defined(__BSD_PROG_MK)
_LIB_OBJTOP=	${ROOTOBJDIR}
.endif
.else
STATIC_CFLAGS+= -ftls-model=local-exec # MIPS/hybrid case
.endif

.if ${MK_CHERI128} == "yes"
_CHERI_COMMON_FLAGS+=	-cheri=128
.else
_CHERI_COMMON_FLAGS+=	-cheri=256
.endif

CFLAGS+=	${CHERI_OPTIMIZATION_FLAGS:U-O2}
# We now need LLD to link any code that uses capabilities:
# We are expanding $LDFLAGS here so this must come after MIPS_ABI has been set!
LDFLAGS:=${LDFLAGS:N-fuse-ld=*}
LDFLAGS+=	-fuse-ld=lld
LDFLAGS+=	-Wl,-preemptible-caprelocs=elf
# Work around cheri-unknown-freebsd-ld.lld: error: section: .init_array is not contiguous with other relro sections
# TODO: remove this once I've debugged the root cause
LDFLAGS+=	-Wl,-z,norelro

# XXX: Needed as Clang rejects -mllvm -cheri128 when using $CC to link:
# warning: argument unused during compilation: '-cheri=128'
_CHERI_CFLAGS+=	-Qunused-arguments
_CHERI_CFLAGS+=	-Werror=cheri-bitwise-operations

.if ${WANT_CHERI} != "variables"
.if ${WANT_CHERI} == "sandbox"
# Force position-dependent sandboxes; PIEs aren't supported
NO_SHARED=	yes
.endif
CC:=	${_CHERI_CC}
CXX:=   ${_CHERI_CXX}
CPP:=	${_CHERI_CPP}
CFLAGS+=	${_CHERI_CFLAGS}
CXXFLAGS+=	${_CHERI_CFLAGS}
# XXXAR: leave this for a while until everyone has updated clang to
# a version that defaults to libc++
CXXFLAGS+=	-stdlib=libc++
# Don't remove CHERI symbols from the symbol table
STRIP_FLAGS+=	-w --keep-symbol=__cheri_callee_method.\* \
		--keep-symbol=__cheri_method.\*
.endif
.endif
.endif
.endif
