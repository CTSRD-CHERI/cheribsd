.PATH:	${SRCTOP}/sys/dev/hwc

KMOD=	hwc

SRCS=	bus_if.h device_if.h vnode_if.h
SRCS+=	hwc_backend.c hwc_context.c hwc_contexthash.c hwc_ioctl.c
SRCS+=	hwc_owner.c hwc_ownerhash.c hwc_vm.c hwc.c

.include <bsd.kmod.mk>
