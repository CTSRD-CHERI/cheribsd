# $FreeBSD$

LCRYPTO_SRC=	${SRCTOP}/crypto/openssl
.PATH: ${LCRYPTO_SRC}/engines ${LCRYPTO_SRC}/engines/ccgost

.ifdef LIBCHERI
SHLIBDIR= /usr/libcheri/engines
.else
SHLIBDIR?= /usr/lib/engines
.endif
