
.PATH: ${SRCTOP}/lib/libc/gen		# for pw_scan.c

PACKAGE=	runtime
PROG=	pwd_mkdb
MAN=	pwd_mkdb.8
SRCS=	pw_scan.c pwd_mkdb.c

CFLAGS+= -I${SRCTOP}/lib/libc/gen		# for pw_scan.h
.if defined(BOOTSTRAPPING)
CFLAGS+=-I${.CURDIR}/bootstrap
.endif

# This is needed to bootstrap on a Linux host:
.if defined(BOOTSTRAPPING) && ${.MAKE.OS} != "FreeBSD"
CFLAGS+=-DNEED_FREEBSD_STRUCT_PASSWD
.endif

.include <bsd.prog.mk>
