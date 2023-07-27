# $FreeBSD$

.PATH:  ${SRCTOP}/sys/dev/hwt

KMOD	= hwt
SRCS	=			\
	hwt.c			\
	hwt_backend.c		\
	hwt_config.c		\
	hwt_context.c		\
	hwt_contexthash.c	\
	hwt_cpu.c		\
	hwt_hook.c		\
	hwt_ioctl.c		\
	hwt_owner.c		\
	hwt_ownerhash.c		\
	hwt_record.c		\
	hwt_thread.c		\
	hwt_vm.c

# EXPORT_SYMS=	hwt_backend_register

.include <bsd.kmod.mk>
