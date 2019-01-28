# $FreeBSD$

SHLIB=	VIQR
SRCS+=	citrus_viqr.c

# Zero length array seems to cause build failure with subobject bounds:
#  error: could not determine size of cap reloc against local object mnemonic_ext
LD_FATAL_WARNINGS=no

.include <bsd.lib.mk>
