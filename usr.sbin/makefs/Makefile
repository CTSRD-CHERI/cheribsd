#	$FreeBSD$

SRCDIR:=${.PARSEDIR:tA}

.include <src.opts.mk>

PROG=	makefs

CFLAGS+=-I${SRCDIR}

SRCS=	cd9660.c \
	ffs.c \
	makefs.c \
	mtree.c \
	walk.c
MAN=	makefs.8

WARNS?=	2

.include "${SRCDIR}/cd9660/Makefile.inc"
.include "${SRCDIR}/ffs/Makefile.inc"
.ifdef BOOTSTRAPPING
# Bootstrapping msdosfs is really awkward since it pulls in tons of kernel
# headers and uses ioctls that might not be available on Linux/macOS
CFLAGS+=	-DWITHOUT_MSDOSFS
.else
.include "${SRCDIR}/msdos/Makefile.inc"
SRCS+=	msdos.c
.endif

CFLAGS+=-DHAVE_STRUCT_STAT_ST_FLAGS=1

.PATH: ${SRCTOP}/contrib/mtree
CFLAGS+=-I${SRCTOP}/contrib/mtree
SRCS+=	getid.c misc.c spec.c

.PATH: ${SRCTOP}/contrib/mknod
CFLAGS+=-I${SRCTOP}/contrib/mknod
SRCS+=	pack_dev.c

CFLAGS+=	-I${SRCTOP}/lib/libnetbsd
LIBADD=		netbsd util sbuf

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
