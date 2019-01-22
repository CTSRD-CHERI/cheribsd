# Build a bootstrap version of m4 (needed in order to build libelf and lex)
.PATH: ${SRCTOP}/usr.bin/m4 ${.CURDIR}

# Avoid using lex or yacc to generate sources
LEX:=/this/should/not/be/used
YACC:=/this/should/not/be/used

tokenizer.c parser.h parser.c: bootstrap_m4_tokenizer_and_parser
	test -e ${.TARGET}

# This target is used as a marker in usr.bin/m4/Makefile to not add the
# lex and yacc includes. Therefore we must define it before including
# the other Makefile. However, we can't the rule here since .for expands any
# variables immediately but the variable is only non-empty after the .include
bootstrap_m4_tokenizer_and_parser:

BINDIR=	/usr/bin
.include "${SRCTOP}/usr.bin/m4/Makefile"

bootstrap_m4_tokenizer_and_parser: ${GENFILES:S/^/init/g}
.for _f in ${GENFILES}
	@cmp -s ${.CURDIR}/init${_f} ${_f} || { \
		echo "Bootstrapping ${_f}" ; \
		${CP} ${.CURDIR}/init${_f} ${_f} ; \
	}
.endfor
