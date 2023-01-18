# $FreeBSD$

.PATH: ${SRCTOP}/lib/libc/iconv

SHLIB_MAJOR= 5
CFLAGS+= -I${SRCTOP}/lib/libc/iconv

CFLAGS+=	-Dbool=_Bool

.if defined(COMPAT_32BIT)
SHLIBDIR= /usr/lib32/i18n
.elif defined(COMPAT_64BIT)
SHLIBDIR= /usr/lib64/i18n
.elif defined(COMPAT_CHERI)
SHLIBDIR= /usr/lib64c/i18n
.else
SHLIBDIR= /usr/lib/i18n
.endif

LIBDIR=	 ${SHLIBDIR}
MK_PROFILE=	no
