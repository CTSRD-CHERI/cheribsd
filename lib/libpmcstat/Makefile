# $FreeBSD$

# XXX: not at all purecap clean, but we need the headers...
MK_WERROR=	no

PACKAGE=lib${LIB}
LIB=	pmcstat
INTERNALLIB=

LIBADD+= xo

SRCS=	\
	libpmcstat_event.c	\
	libpmcstat_image.c	\
	libpmcstat_logging.c	\
	libpmcstat_process.c	\
	libpmcstat_string.c	\
	libpmcstat_symbol.c

# If libpmcstat becomes public uncomment this line
#INCS=	libpmcstat.h

.include <bsd.lib.mk>
