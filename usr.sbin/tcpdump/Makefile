.include <src.opts.mk>

SUBDIR=	libnetdissect .WAIT tcpdump
.if (${MACHINE_ABI:Mpurecap} && ${MACHINE_ABI:Mbenchmark}) || ${MK_LIB64CB} == "yes"
SUBDIR+=tcpdump-benchmark
.endif

.include <bsd.subdir.mk>
