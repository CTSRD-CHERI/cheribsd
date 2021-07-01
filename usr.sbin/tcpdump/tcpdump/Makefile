# $FreeBSD$

.include <src.opts.mk>

TCPDUMP_DISTDIR?= ${SRCTOP}/contrib/tcpdump
.PATH: ${TCPDUMP_DISTDIR}

PROG=	tcpdump

SRCS=	\
	ascii_strcasecmp.c \
	gmt2local.c \
	machdep.c \
	netdissect.c \
	setsignal.c \
	strtoaddr.c \
	tcpdump.c \
	version.c
CLEANFILES+=	version.c ${MAN}

.include "Makefile.print"

CFLAGS+= -I${.CURDIR} -I${TCPDUMP_DISTDIR}
CFLAGS+= -DHAVE_CONFIG_H
CFLAGS+= -D_U_="__attribute__((unused))"

.if ${MACHINE_CPUARCH} != "i386"
CFLAGS+=	-DLBL_ALIGN
.endif

LIBADD=	pcap
.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_dns
CFLAGS+=-DHAVE_CASPER
.endif
.if ${MK_OPENSSL} != "no"
LIBADD+=	crypto
CFLAGS+= -I${SYSROOT:U${DESTDIR}}/usr/include/openssl
CFLAGS+= -DHAVE_LIBCRYPTO -DHAVE_OPENSSL_EVP_H
.endif

.ifdef OAKLAND2015
CFLAGS+=	-DTCPDUMP_BENCHMARKING
.endif

version.c: ${TCPDUMP_DISTDIR}/VERSION
	rm -f version.c ; \
	    sed 's/.*/char version[] = "&";/' ${TCPDUMP_DISTDIR}/VERSION \
		> version.c

.include <bsd.prog.mk>

.for mp in ${MAN}
${mp}: ${mp}.in
	sed -e 's/@MAN_MISC_INFO@/7/g' -e 's/@MAN_FILE_FORMATS@/5/g' \
		${.ALLSRC} > ${.TARGET}
.endfor
