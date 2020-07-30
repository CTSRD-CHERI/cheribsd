# $FreeBSD$

MDSRCS+= \
	ffs.S \
	strlen.S

.if ! ${MACHINE_ABI:Mpurecap}
MDSRCS+= \
	bcmp.S \
	bzero.S \
	memset.S \
	strchr.S \
	strcmp.S \
	strrchr.S
.endif

.if ${MACHINE_CPU:Mcheri}
.if !${MACHINE_ABI:Mpurecap}
CHERI_MDSRCS=	\
		memcpy_c.c \
		memmove_c.c \
		memset_c.c
.endif

CHERI_MISRCS=	\
		bcopy.c \
		memcpy.c \
		memmove.c \

MDSRCS+=	${CHERI_MDSRCS}

.if ! ${MACHINE_ABI:Mpurecap}
.for src in ${CHERI_MDSRCS} ${CHERI_MISRCS}
CC.${src}=	${CC} -target mips64-unknown-freebsd -cheri
.endfor
.endif

SYM_MAPS+=	${LIBC_SRCTOP}/mips/string/Symbol.map
.endif
