# $FreeBSD$

LIB=	cheri

WANT_DUMP=      yes
NO_SHARED=	yes

SRCS=	cheri_ccall.c			\
	cheri_ccall_trampoline.S	\
	cheri_enter.c			\
	cheri_fd.c			\
	cheri_stack.c			\
	cheri_stack_md.c		\
	cheri_system.c			\
	cheri_type.c			\
	error.cc			\
	libcheri_init.c			\
	sandbox.c			\
	sandbox_elf.c			\
	sandbox_loader.c		\
	sandbox_methods.c		\

.if defined(LIBCHERI)
SRCS+=	cheri_invoke_cabi.S		\
	libcheri_classes_cabi.S
.else
SRCS+=	cheri_invoke_hybrid.S		\
	libcheri_classes_hybrid.S
.endif

INCS=	cheri_ccall.h			\
	cheri_class.h			\
	cheri_enter.h			\
	cheri_errno.h			\
	cheri_fd.h			\
	cheri_invoke.h			\
	cheri_memcpy.h			\
	cheri_stack.h			\
	cheri_system.h			\
	cheri_system_md.h		\
	cheri_type.h			\
	libcheri_init.h			\
	sandbox.h			\
	sandbox_internal.h		\
	sandboxasm.h

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/${MACHINE_ARCH}
CFLAGS.cheri_invoke_hybrid.S+= -fno-pic -mabicalls
CFLAGS+=  -mllvm -mxmxgot
CFLAGS+=	-DHAVE_WORKING_TLS

INCSDIR=	${INCLUDEDIR}/cheri

CFLAGS+=	-I${.CURDIR}/../libc/include \
		-I${.CURDIR}/../libc/locale

SHLIB_MAJOR=	1

MAN=	cheri_invoke.3			\
	libcheri.3

.if !defined(NEED_CHERI)
NEED_CHERI=	hybrid
.endif

CLEANFILES=	cheri_ccall_trampoline.o
.if defined(LIBCHERI)
CLEANFILES+=	cheri_invoke_cabi.o		\
		libcheri_classes_cabi.o
.else
CLEANFILES+=	cheri_invoke_hybrid.o		\
		libcheri_classes_hybrid.o
.endif

NO_WERROR=

.PATH: ${.CURDIR}/${MACHINE_ARCH}
.PATH: ${.CURDIR}/../libc/string
.PATH: ${.CURDIR}/../libc/${MACHINE}/string

.include <bsd.lib.mk>
