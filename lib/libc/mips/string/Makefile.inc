# $FreeBSD$

MDSRCS+= \
	ffs.S \
	strlen.S

.if ! ${MACHINE_ABI:Mpurecap}
MDSRCS+= \
	bcmp.S \
	bzero.S \
	memset.S \
	strchr.S \
	strcmp.S \
	strrchr.S
.endif
