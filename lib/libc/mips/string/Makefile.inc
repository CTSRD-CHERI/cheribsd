# $FreeBSD$

MDSRCS+= \
	ffs.S \
	strlen.S

.if ! ${MACHINE_ARCH:Mmips*c*}
MDSRCS+= \
	bcmp.S \
	bzero.S \
	memset.S \
	strchr.S \
	strcmp.S \
	strrchr.S
.endif

.if ${MACHINE_ARCH:Mmips*c*} || ${MK_CHERI} == "yes"
CHERI_MDSRCS=	\
		memchr_c.c \
		memcmp_c.c \
		memcpy_c.c \
		memcpy_c_tofrom.c \
		memmove_c.c \
		memset_c.c \
		strchr_c.c \
		strcmp_c.c \
		strnlen_c.c \
		strncmp_c.c \
		strncpy_c.c \
		strtol_c.c
CHERI_MISRCS=	\
		bcopy.c \
		memcpy.c \
		memmove.c \

MDSRCS+=	${CHERI_MDSRCS}

.if ! ${MACHINE_ARCH:Mmips*c*}
.if ${MK_CHERI128} == "yes"
_CHERIBITS=128
.else
_CHERIBITS=256
.endif
.for src in ${CHERI_MDSRCS} ${CHERI_MISRCS}
CC.${src}=	${CC} -target cheri-unknown-freebsd -cheri=${_CHERIBITS}
.endfor
.endif

SYM_MAPS+=	${LIBC_SRCTOP}/mips/string/Symbol.map
.endif
