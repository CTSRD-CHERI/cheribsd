# $FreeBSD$

.include <bsd.compiler.mk>

.PATH: ${SRCTOP}/sys/dev/isp

KMOD=	isp
SRCS=	bus_if.h device_if.h pci_if.h \
	opt_cam.h opt_ddb.h opt_isp.h \
	isp.c isp_library.c isp_target.c isp_freebsd.c isp_pci.c

.if ${MACHINE} == sparc64
SRCS+=	isp_sbus.c ofw_bus_if.h
.endif

.if ${COMPILER_TYPE} == "clang" && ${COMPILER_VERSION} >= 100000
# Silence spurious warning (array of bytes accessed as 32-bit words).
CFLAGS+=	-Wno-sizeof-array-div
.endif

.include <bsd.kmod.mk>
