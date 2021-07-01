# $FreeBSD$

LIB=	cheri

NO_SHARED=	yes

SRCS=	libcheri_ccall.c		\
	libcheri_ccall_trampoline.S	\
	libcheri_enter.c		\
	libcheri_fd.c			\
	libcheri_init.c			\
	libcheri_stack.c		\
	libcheri_stack_md.c		\
	libcheri_system.c		\
	libcheri_type.c			\
	libcheri_error.cc		\
	libcheri_sandbox.c		\
	libcheri_sandbox_elf.c		\
	libcheri_sandbox_loader.c	\
	libcheri_sandbox_methods.c

.if ${MACHINE_ABI:Mpurecap}
SRCS+=	libcheri_invoke_cabi.S		\
	libcheri_classes_cabi.S
.else
SRCS+=	libcheri_invoke_hybrid.S	\
	libcheri_classes_hybrid.S
.endif

INCS=	libcheri_ccall.h		\
	libcheri_class.h		\
	libcheri_enter.h		\
	libcheri_errno.h		\
	libcheri_fd.h			\
	libcheri_invoke.h		\
	libcheri_stack.h		\
	libcheri_system.h		\
	libcheri_system_md.h		\
	libcheri_type.h			\
	libcheri_init.h			\
	libcheri_sandbox.h		\
	libcheri_sandbox_internal.h	\
	libcheri_sandbox_metadata.h	\
	libcheri_sandboxasm.h

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${.CURDIR}/${MACHINE}
CFLAGS.libcheri_invoke_hybrid.S+= -fno-pic -mabicalls
CFLAGS+=  -mllvm -mxmxgot
CFLAGS+=	-DHAVE_WORKING_TLS

INCSDIR=	${INCLUDEDIR}/cheri

CFLAGS+=	-I${.CURDIR}/../libc/include \
		-I${.CURDIR}/../libc/locale

SHLIB_MAJOR=	1

MAN=	libcheri_invoke.3		\
	libcheri.3

CLEANFILES=	libcheri_ccall_trampoline.o
.if ${MACHINE_ABI:Mpurecap}
CLEANFILES+=	libcheri_invoke_cabi.o		\
		libcheri_classes_cabi.o
.else
CLEANFILES+=	libcheri_invoke_hybrid.o	\
		libcheri_classes_hybrid.o
.endif

.PATH: ${.CURDIR}/${MACHINE}
.PATH: ${.CURDIR}/../libc/string
.PATH: ${.CURDIR}/../libc/${MACHINE}/string

.include "../Makefile.inc"
.include <bsd.lib.mk>
