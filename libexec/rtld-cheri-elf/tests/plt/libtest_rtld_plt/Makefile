# $FreeBSD$

SRCS+=write.S data.c functions.c
SHLIB=		test_rtld_plt
SHLIB_MAJOR=	1

.if exists(${SRCTOP}/lib/libc/${MACHINE_ARCH})
RTLD_ARCH=	${MACHINE_ARCH}
.else
RTLD_ARCH=	${MACHINE_CPUARCH}
.endif
CFLAGS+=	-I${SRCTOP}/lib/libc/${RTLD_ARCH}

# create the install directory without mtree:
PACKAGE=	tests
FILESGROUPS+=	${PACKAGE}FILES
${PACKAGE}FILESPACKAGE=	${PACKAGE}
${PACKAGE}FILESDIR=	${TESTSDIR}

SHLIBDIR=	${TESTSDIR}
LIBDIR=	${TESTSDIR}

CHERI_USE_CAP_TABLE:=plt
.include <bsd.lib.mk>
# This needs to be done after bsd.cheri.mk (so that it works even if we pass
# CHERI_USE_CAP_TABLE on the make command line)
CFLAGS:=	${CFLAGS:N-cheri-cap-table-abi=*} -cheri-cap-table-abi=plt
