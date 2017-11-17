# $FreeBSD$

WARNS?=		6

.if ${MK_CHERI_PURE} == "yes"
WANT_CHERI?=pure
.endif
