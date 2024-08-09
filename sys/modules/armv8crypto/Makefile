.PATH: ${SRCTOP}/sys/crypto/armv8
.PATH: ${SRCTOP}/sys/crypto/openssl/aarch64

KMOD=	armv8crypto
SRCS=	armv8_crypto.c
SRCS+=	device_if.h bus_if.h opt_bus.h cryptodev_if.h

OBJS+=	armv8_crypto_wrap.o aesv8-armx.o ghashv8-armx.o

CFLAGS+=-I${SRCTOP}/sys/crypto/openssl

CFLAGS_CRYPTO=	${CFLAGS:M-march=*:S/^$/-march=armv8-a/W:[-1]}+crypto

# Remove -nostdinc so we can get the intrinsics.
armv8_crypto_wrap.o: armv8_crypto_wrap.c
	${CC} -c ${CFLAGS:C/^-O2$/-O3/:N-nostdinc:N-mgeneral-regs-only} \
	    -I${SRCTOP}/sys/crypto/armv8 \
	    ${WERROR} ${PROF} \
	    ${CFLAGS_CRYPTO} ${.IMPSRC}
	${CTFCONVERT_CMD}

aesv8-armx.o: aesv8-armx.S
	${CC} -c ${CFLAGS:C/^-O2$/-O3/:N-nostdinc:N-mgeneral-regs-only} \
	    -I${SRCTOP}/sys/crypto/armv8 \
	    ${WERROR} ${PROF} \
	    ${CFLAGS_CRYPTO} ${.IMPSRC}
	${CTFCONVERT_CMD}

ghashv8-armx.o: ghashv8-armx.S
	${CC} -c ${CFLAGS:C/^-O2$/-O3/:N-nostdinc:N-mgeneral-regs-only} \
	    -I${SRCTOP}/sys/crypto/armv8 \
	    ${WERROR} ${PROF} \
	    ${CFLAGS_CRYPTO} ${.IMPSRC}
	${CTFCONVERT_CMD}

armv8_crypto_wrap.o: armv8_crypto.h

.include <bsd.kmod.mk>
