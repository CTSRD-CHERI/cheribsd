# $FreeBSD$

PROG=	linker-set-test
SRCS=	linker-set-test.c
MAN=
NO_PIC=
MK_PIE=no
OBJS+=	entries_blob.o
CLEANFILES+=	entries_blob.o entries.o entry_foo.o entry_bar.o

entries_blob.o: entries.o entry_foo.o entry_bar.o
	${CC:N${CCACHE_BIN}} -nostdlib ${LDFLAGS} -o ${.TARGET} \
	    -r -Wl,--whole-archive ${.ALLSRC}

.include <bsd.prog.mk>
