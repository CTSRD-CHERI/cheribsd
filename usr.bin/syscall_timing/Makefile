# $FreeBSD$

.PATH: ${SRCTOP}/tools/tools/syscall_timing

PROG=	syscall_timing
MAN=

LIBADD=		statcounters
CFLAGS+=	-DWITH_LIBSTATCOUNTERS
CFLAGS+=	-fPIE -pie -Wno-error=deprecated-declarations -fuse-ld=lld
NEED_CHERI=	hybrid
MK_CHERI_SHARED_PROG:=yes

WARNS=	6

.include <bsd.prog.mk>
