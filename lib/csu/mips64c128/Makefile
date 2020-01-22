#
# $FreeBSD$
#
FILESOWN=       ${LIBOWN}
FILESGRP=       ${LIBGRP}
FILESMODE=      ${LIBMODE}
FILESDIR=       ${LIBDIR}
# These FILES qualify as libraries for the purpose of LIBRARIES_ONLY.
.undef LIBRARIES_ONLY
CLEANFILES=	${FILES}
CFLAGS+=-mxgot -mllvm -mxmxgot
CFLAGS+=	-DCRT_IRELOC_SUPPRESS

.if !${MACHINE_ARCH:Mmips*c*}
NEED_CHERI=	pure
.endif

NO_BSD_CRTBEGIN=	yes
.PATH:	${.CURDIR}/../common-cheri
CFLAGS+=	-I${.CURDIR}/../common		\
		-I${.CURDIR}/../common-cheri	\
		-I${.CURDIR}/../../libc/include
FILES+=	crt1.o					\
	Scrt1.o					\
	crtbegin.o				\
	crtbeginS.o				\
	crtbeginT.o				\
	crtend.o				\
	crtendS.o

PICFLAG+=-DPOSITION_INDEPENDENT_STARTUP=1

# Used for executables if neither -static nor -pie is passed
crtbegin.o:	crtbeginC.c
	${CC} ${CFLAGS} -c -o ${.TARGET} ${.ALLSRC}

# Used for executables with -pie or libraries with -shared
crtbeginS.o:	crtbeginC.c
	${CC} ${CFLAGS} -DSHLIB_INIT ${PICFLAG} -c -o ${.TARGET} ${.ALLSRC}

# Used for executables if -static is passed
crtbeginT.o:	crtbeginC.c
	${CC} ${CFLAGS} -c -o ${.TARGET} ${.ALLSRC}

# Added to the end of the linker command line for PIE and shared libraries
crtendS.o:	crtendC.c
	${CC} ${CFLAGS} ${PICFLAG} -c -o ${.TARGET} ${.ALLSRC}

# Added to the end of the linker command line for executales without -pie
crtend.o:	crtendC.c
	${CC} ${CFLAGS} -c -o ${.TARGET} ${.ALLSRC}

# Used as the first object file for PIE (other executables use crt1.c)
Scrt1.o:	crt1.c
	${CC} ${CFLAGS} ${PICFLAG} -c -o ${.TARGET} ${.ALLSRC}

.include <bsd.lib.mk>
