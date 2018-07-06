# $FreeBSD$

SRCS+=	main.c metadata.c

.PATH:		${UBOOTSRC}/common

CFLAGS+=	-I${UBOOTSRC}/common

# U-Boot standalone support library
LIBUBOOT=	${BOOTOBJ}/uboot/lib/libuboot.a
CFLAGS+=	-I${UBOOTSRC}/lib
CFLAGS+=	-I${BOOTOBJ}/uboot/lib

.include "${BOOTSRC}/fdt.mk"

.if ${MK_FDT} == "yes"
LIBUBOOT_FDT=	${BOOTOBJ}/uboot/fdt/libuboot_fdt.a
.endif
