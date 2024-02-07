# PUBLIC DOMAIN - NO WARRANTY, see:
#     <http://creativecommons.org/publicdomain/zero/1.0/>
#
# Written in 2023 by Alfonso Sabato Siciliano

OUTPUT =  bsddialog
export VERSION=1.0
.CURDIR ?= ${CURDIR}
LIBPATH = ${.CURDIR}/lib
LIBBSDDIALOG = ${LIBPATH}/libbsddialog.so
UTILITYPATH = ${.CURDIR}/utility

RM= rm -f
LN = ln -s -f

### cli options ###
# port/pkg Makefile: 'MAKE_ARGS = -DNORPATH'
NORPATH ?=
export DISABLERPATH=${NORPATH}
# `make -DDEBUG`
# `gmake DEBUG=1`
DEBUG ?=
export ENABLEDEBUG=${DEBUG}

all : ${OUTPUT}

${OUTPUT}: ${LIBBSDDIALOG}
	${MAKE} -C ${UTILITYPATH} LIBPATH=${LIBPATH}
	${LN} ${UTILITYPATH}/${OUTPUT} ${.CURDIR}/${OUTPUT}

${LIBBSDDIALOG}:
	${MAKE} -C ${LIBPATH}

clean:
	${MAKE} -C ${LIBPATH} clean
	${MAKE} -C ${UTILITYPATH} clean
	${RM} ${OUTPUT} *.core

