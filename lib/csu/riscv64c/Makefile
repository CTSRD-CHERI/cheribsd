# $FreeBSD$

.PATH:	${.CURDIR}/../common-cheri ${.CURDIR}/../common

OBJS=		Scrt1.o crt1.o
CFLAGS+=	-I${.CURDIR} -I${.CURDIR:H}/common \
		-I${.CURDIR:H}/common-cheri \
		-I${SRCTOP}/lib/libc/include
CFLAGS+=	-DCRT_IRELOC_SUPPRESS
# Purecap code requires crt_init_globals to be called before using jump tables
CFLAGS+=	-fno-jump-tables

FILES=		${OBJS}
FILESMODE=      ${LIBMODE}
FILESOWN=       ${LIBOWN}
FILESGRP=       ${LIBGRP}
FILESDIR=       ${LIBDIR}
# These FILES qualify as libraries for the purpose of LIBRARIES_ONLY.
.undef LIBRARIES_ONLY

CLEANFILES+=	${OBJS} crt1_c.o Scrt1_c.o
CLEANFILES+=	crtbrand.o ignore_init_note.o

PICFLAG+=-DPOSITION_INDEPENDENT_STARTUP=1

crt1.o:	crt1_c.o crtbrand.o ignore_init_note.o
	${LD} ${_LDFLAGS} -o crt1.o -r crtbrand.o ignore_init_note.o crt1_c.o

Scrt1_c.o: crt1_c.c
	${CC} ${CFLAGS} ${PICFLAG} -c -o ${.TARGET} ${.CURDIR}/crt1_c.c

Scrt1.o: Scrt1_c.o crtbrand.o ignore_init_note.o
	${LD} ${_LDFLAGS} -o Scrt1.o -r crtbrand.o ignore_init_note.o Scrt1_c.o

.include <bsd.lib.mk>
