# $Id: man.mk,v 1.25 2021/10/31 03:03:14 sjg Exp $

.if !target(__${.PARSEFILE}__)
__${.PARSEFILE}__: .NOTMAIN

OPTIONS_DEFAULT_NO += CMT2DOC

.include <init.mk>
.include <options.mk>

# unlike bsd.man.mk we handle 3 approaches
# 1. install unformated nroff (default)
# 2. install formatted pages
# 3. install formatted pages but with extension of .0
# sadly we cannot rely on a shell that supports ${foo#...} and ${foo%...}
# so we have to use sed(1).

# set MANTARGET=cat for formatted pages
MANTARGET?=	man
# set this to .0 for same behavior as bsd.man.mk
MCATEXT?=

NROFF?=		nroff
MANDIR?=	/usr/share/man
MANDOC?= man

MAN_SUFFIXES?= .1 .2 .3 .4 .5 .6 .7 .8 .9
.SUFFIXES: ${MAN_SUFFIXES}
.if ${MANTARGET} == "cat"
.SUFFIXES: ${MAN_SUFFIXES:S,.,.cat,}
.endif

${MAN_SUFFIXES:@s@$s${s:S,.,.cat,}@}:
	@echo "${NROFF} -${MANDOC} ${.IMPSRC} > ${.TARGET:T}"
	@${NROFF} -${MANDOC} ${.IMPSRC} > ${.TARGET:T}.new && \
	mv ${.TARGET:T}.new ${.TARGET:T}

.if defined(MAN) && !empty(MAN)

.if ${MK_CMT2DOC} == "yes"
# use cmt2doc.py to extract manpages from source
CMT2DOC?= cmt2doc.py
CMT2DOC_OPTS?=  ${CMT2DOC_ORGOPT} -pmS${.TARGET:E}
CMT2DOC_SUFFIXES+= .c .h .sh .pl .py

.SUFFIXES: ${CMT2DOC_SUFFIXES}

${CMT2DOC_SUFFIXES:@s@${MAN_SUFFIXES:@m@$s$m@}@}:
	@echo "${CMT2DOC} ${.IMPSRC} > ${.TARGET:T}"
	@${CMT2DOC} ${CMT2DOC_OPTS} ${.IMPSRC} > ${.TARGET:T}.new && \
	mv ${.TARGET:T}.new ${.TARGET:T}

.endif

_mandir=${DESTDIR}${MANDIR}/${MANTARGET}`echo $$page | sed -e 's/.*\.cat/./' -e 's/.*\.//'`
.if ${MANTARGET} == "cat"
_mfromdir?=.
MANALL=	${MAN:${MAN_SUFFIXES:S,.,,:@m@S/.$m/.cat$m/@:ts:}}
.if ${MCATEXT} == ""
_minstpage=`echo $$page | sed 's/\.cat/./'`
.else
_minstpage=`echo $$page | sed 's/\.cat.*//'`${MCATEXT}
.endif
.endif
.if target(${MAN:[1]})
_mfromdir?=.
.endif
_mfromdir?=${.CURDIR}
MANALL?= ${MAN}
_minstpage?=$${page}
.endif

.if !empty(MANOWN)
MAN_INSTALL_OWN ?= -o ${MANOWN} -g ${MANGRP}
MAN_CHOWN ?= chown
.else
MAN_CHOWN = :
.endif

MINSTALL=	${INSTALL} ${COPY} ${MAN_INSTALL_OWN} -m ${MANMODE}
.if defined(MANZ)
# chown and chmod are done afterward automatically
MCOMPRESS=	gzip -cf
MCOMPRESSSUFFIX= .gz
.endif

maninstall:
.if defined(MANALL) && !empty(MANALL)
	@for page in ${MANALL:T}; do \
		test -s ${_mfromdir}/$$page || continue; \
		dir=${_mandir}; \
		test -d $$dir || ${INSTALL} -d ${MAN_INSTALL_OWN} -m 775 $$dir; \
		instpage=$${dir}${MANSUBDIR}/${_minstpage}${MCOMPRESSSUFFIX}; \
		if [ X"${MCOMPRESS}" = X ]; then \
			echo ${MINSTALL} ${_mfromdir}/$$page $$instpage; \
			${MINSTALL} ${_mfromdir}/$$page $$instpage; \
		else \
			rm -f $$instpage; \
			echo ${MCOMPRESS} ${_mfromdir}/$$page \> $$instpage; \
			${MCOMPRESS} ${_mfromdir}/$$page > $$instpage; \
			${MAN_CHOWN} ${MANOWN}:${MANGRP} $$instpage; \
			chmod ${MANMODE} $$instpage; \
		fi \
	done
.if defined(MLINKS) && !empty(MLINKS)
	@set ${MLINKS}; \
	while test $$# -ge 2; do \
		page=$$1; \
		shift; \
		dir=${_mandir}; \
		l=${_minstpage}${MCOMPRESSSUFFIX}; \
		page=$$1; \
		shift; \
		dir=${_mandir}; \
		t=$${dir}${MANSUBDIR}/${_minstpage}${MCOMPRESSSUFFIX}; \
		echo $$t -\> $$l; \
		rm -f $$t; \
		ln -s $$l $$t; \
	done
.endif
.endif

.if defined(MANALL) && !empty(MANALL)
manall: ${MANALL}
all: manall
.endif

.if defined(CLEANMAN) && !empty(CLEANMAN)
cleandir: cleanman
cleanman:
	rm -f ${CLEANMAN}
.endif
.endif
