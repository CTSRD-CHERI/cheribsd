# $FreeBSD$

.include <src.opts.mk>

COMPILERRTDIR=	${SRCTOP}/contrib/llvm-project/compiler-rt

_USE_CHERI_LIBUNWIND=0
.if ${MK_CHERI} != "no"
WANT_CHERI?=	hybrid
_USE_CHERI_LIBUNWIND=1
.elif (${MACHINE_ARCH:Mmips*} || ${MACHINE_ABI:Mpurecap})
_USE_CHERI_LIBUNWIND=1
.endif

.if ${_USE_CHERI_LIBUNWIND}
UNWINDINCDIR=	${SRCTOP}/contrib/subrepo-cheri-libunwind/include
UNWINDSRCDIR=	${SRCTOP}/contrib/subrepo-cheri-libunwind/src
.else
UNWINDINCDIR=	${SRCTOP}/contrib/llvm-project/libunwind/include
UNWINDSRCDIR=	${SRCTOP}/contrib/llvm-project/libunwind/src
.endif

STATIC_CFLAGS+=${PICFLAG} -fvisibility=hidden -DVISIBILITY_HIDDEN

.PATH: ${COMPILERRTDIR}/lib/builtins
.PATH: ${UNWINDSRCDIR}
SRCS_EXC+=	gcc_personality_v0.c
SRCS_EXC+=	Unwind-EHABI.cpp
SRCS_EXC+=	Unwind-sjlj.c
SRCS_EXC+=	UnwindLevel1-gcc-ext.c
SRCS_EXC+=	UnwindLevel1.c
SRCS_EXC+=	UnwindRegistersRestore.S
SRCS_EXC+=	UnwindRegistersSave.S
SRCS_EXC+=	libunwind.cpp

SRCS+=		${SRCS_EXC}
.for file in ${SRCS_EXC:M*.c}
CFLAGS.${file}+=	-fno-exceptions -funwind-tables
.endfor
.for file in ${SRCS_EXC:M*.cpp}
CXXFLAGS.${file}+=	-fno-exceptions -funwind-tables
.endfor

CFLAGS+=	-I${UNWINDINCDIR}
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-D_LIBUNWIND_IS_NATIVE_ONLY
CFLAGS+=	-D_LIBUNWIND_USE_FRAME_HEADER_CACHE
CXXFLAGS+=	-fno-rtti
CXXSTD?=	c++11
STATIC_CXXFLAGS+= -fvisibility=hidden -fPIC
# Probably need to just move this earlier or use CXXFLAGS
.if ${MK_DIRDEPS_BUILD} == "yes"
# Avoid dependency on lib/libc++
.if ${_USE_CHERI_LIBUNWIND}
CFLAGS+=	-isystem ${SRCTOP}/contrib/subrepo-cheri-libc++/include -nostdinc++
.else
CFLAGS+=	-isystem ${SRCTOP}/contrib/llvm-project/libcxx/include -nostdinc++
.endif
.endif
