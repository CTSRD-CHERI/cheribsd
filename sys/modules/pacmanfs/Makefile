.PATH: ${SRCTOP}/sys/fs/pacmanfs

KMOD?=	pacmanfs
SRCS=	pacmanfs.c
SRCS+=	${LINUXKPI_GENSRCS}

CFLAGS+=	${LINUXKPI_INCLUDES}

.include <bsd.kmod.mk>
