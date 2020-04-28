# $FreeBSD$

LIB=	linker_set_test
SRCS=	dummy.c
MAN=
NO_PIC=
MK_PROFILE=	no

OBJS+=	entries_blob.o
CLEANFILES+=	entries_blob.o entries.o entry_foo.o entry_bar.o

entries_blob.o: entries.o entry_foo.o entry_bar.o
	${CC:N${CCACHE_BIN}} -nostdlib ${LDFLAGS} -o ${.TARGET} \
	    -r -Wl,--whole-archive ${.ALLSRC}

.include <bsd.lib.mk>
