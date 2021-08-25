# $FreeBSD$

.include <bsd.init.mk>

LIB=		clang_rt.profile-${CRTARCH}

CFLAGS+=	-DCOMPILER_RT_HAS_ATOMICS=1
CFLAGS+=	-DCOMPILER_RT_HAS_FCNTL_LCK=1
CFLAGS+=	-DCOMPILER_RT_HAS_UNAME=1

# This is needed for --coverage
CXXFLAGS+=	-fvisibility=default

SRCS+=		profile/GCDAProfiling.c
SRCS+=		profile/InstrProfiling.c
.if 1
# Removed in LLVM 13
SRCS+=		profile/InstrProfilingBiasVar.c
.endif
SRCS+=		profile/InstrProfilingBuffer.c
SRCS+=		profile/InstrProfilingFile.c
SRCS+=		profile/InstrProfilingInternal.c
SRCS+=		profile/InstrProfilingMerge.c
SRCS+=		profile/InstrProfilingMergeFile.c
SRCS+=		profile/InstrProfilingNameVar.c
SRCS+=		profile/InstrProfilingPlatformLinux.c
SRCS+=		profile/InstrProfilingPlatformOther.c
SRCS+=		profile/InstrProfilingRuntime.cpp
SRCS+=		profile/InstrProfilingUtil.c
SRCS+=		profile/InstrProfilingValue.c
.if 0
# Added in LLVM 13
SRCS+=		profile/InstrProfilingVersionVar.c
.endif
SRCS+=		profile/InstrProfilingWriter.c

.PATH:		${CRTSRC}/include/profile
INCSDIR=	${CLANGDIR}/include/profile
INCS+=		InstrProfData.inc

.include <bsd.lib.mk>
