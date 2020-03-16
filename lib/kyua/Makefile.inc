KYUALIBDIR:=	${.PARSEDIR}
KYUASRCDIR=	${SRCTOP}/contrib/subrepo-kyua

LIB_CXX=        kyua_${KYUALIB}
INTERNALLIB=

.PATH: ${KYUASRCDIR}/${KYUALIB}
CFLAGS+=	-I${KYUALIBDIR} \
		-I${KYUASRCDIR}	\
		-I${SRCTOP}/contrib/subrepo-lutok/include

CFLAGS+=	-DHAVE_CONFIG_H

# kyua uses auto_ptr
CFLAGS+=        -Wno-deprecated-declarations

.include "${KYUALIBDIR}/Makefile.kyua"
.include "${.PARSEDIR}/../Makefile.inc"
