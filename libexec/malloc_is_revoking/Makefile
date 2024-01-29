.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap}
NEED_COMPAT=    64C
.include <bsd.compat.mk>
.endif

PROG=	${.CURDIR:T}
MAN=

.PATH: ${.CURDIR}/..
SRCS=	malloc_is_revoking.c

NO_SHARED=	malloc_revocation override only works in static binaries

${PROG}_elfnote_disable: ${PROG}
	cp ${.ALLSRC} ${.TARGET}
	${ELFCTL} -e +nocherirevoke ${.TARGET} || rm -f ${.TARGET}

${PROG}_elfnote_enable: ${PROG}
	cp ${.ALLSRC} ${.TARGET}
	${ELFCTL} -e +cherirevoke ${.TARGET} || rm -f ${.TARGET}

${PROG}_suid: ${PROG}
	cp ${.ALLSRC} ${.TARGET}

${PROG}_suid_elfnote_disable: ${PROG}_elfnote_disable
	cp ${.ALLSRC} ${.TARGET}

${PROG}_suid_elfnote_enable: ${PROG}_elfnote_enable
	cp ${.ALLSRC} ${.TARGET}


FILESGROUPS=	ELFNOTE ELFNOTE_SUID
CLEANFILES=	${ELFNOTE} ${ELFNOTE_SUID}

ELFNOTE=	${PROG}_elfnote_disable ${PROG}_elfnote_enable
ELFNOTEOWN=	${BINOWN}
ELFNOTEMODE=	${BINMODE}
ELFNOTEDIR=	${BINDIR}

ELFNOTE_SUID= \
	${PROG}_suid \
	${PROG}_suid_elfnote_disable \
	${PROG}_suid_elfnote_enable
ELFNOTE_SUIDOWN=	nobody
ELFNOTE_SUIDMODE=	4555
ELFNOTE_SUIDDIR=	${BINDIR}

.include <bsd.prog.mk>
