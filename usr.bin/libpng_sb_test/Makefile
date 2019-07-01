# $FreeBSD$

PROG=	libpng_sb_test

# Cannot use R_MIPS_LO16, etc. relocations in text segment
# They are not supported by RTLD
NO_SHARED=     yes

MAN=

WARNS=	6

LIBADD=	png_sb cheri
CFLAGS+=        -I${SRCTOP}/contrib/libpng
CFLAGS+=        -I${SRCTOP}/lib/libpng

.include <bsd.prog.mk>
