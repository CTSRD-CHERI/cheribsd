.include <src.opts.mk>

TCPDUMP_DISTDIR?= ${SRCTOP}/contrib/tcpdump
.PATH: ${TCPDUMP_DISTDIR}

PROG=	tcpdump

SRCS=	\
	addrtoname.c \
	fptype.c \
	machdep.c \
	tcpdump.c

CLEANFILES+=	${MAN}

CFLAGS+= -I${.CURDIR:H} -I${TCPDUMP_DISTDIR}
CFLAGS+= -DHAVE_CONFIG_H
CFLAGS+= -D_U_="__attribute__((unused))"

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+=	-DINET6 -DHAVE_OS_IPV6_SUPPORT
.endif

LIBADD=	pcap
LIBADD+=	netdissect
.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_dns
CFLAGS+=-DHAVE_CASPER
.endif
.if ${MK_OPENSSL} != "no"
LIBADD+=	crypto
CFLAGS+= -I${SYSROOT:U${DESTDIR}}/usr/include/openssl
CFLAGS+= -DHAVE_LIBCRYPTO -DHAVE_OPENSSL_EVP_H
CFLAGS+= -DOPENSSL_API_COMPAT=0x10100000L
.endif

.include <bsd.prog.mk>

.for mp in ${MAN}
${mp}: ${mp}.in
	sed -e 's/@MAN_MISC_INFO@/7/g' -e 's/@MAN_FILE_FORMATS@/5/g' \
		${.ALLSRC} > ${.TARGET}
.endfor
