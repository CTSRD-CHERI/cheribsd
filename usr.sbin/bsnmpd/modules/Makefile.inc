# $FreeBSD$

SHLIB_MAJOR=	6
PACKAGE=	bsnmp
LD_FATAL_WARNINGS=no

MANFILTER=	sed -e 's%@MODPATH@%${LIBDIR}/%g'		\
		    -e 's%@DEFPATH@%${DEFSDIR}/%g'		\
		    -e 's%@MIBSPATH@%${BMIBSDIR}/%g'

NO_WMISSING_VARIABLE_DECLARATIONS=

.include "../Makefile.inc"
