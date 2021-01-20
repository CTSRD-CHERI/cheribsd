# $FreeBSD$

.if ${MACHINE_ABI:Mpurecap}
CFLAGS+=	-DRTLD_HAS_CAPRELOCS
.endif
