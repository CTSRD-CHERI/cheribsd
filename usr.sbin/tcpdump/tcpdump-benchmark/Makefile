.include <src.opts.mk>

PROG=	tcpdump-benchmark
MAN=

.if !${MACHINE_ABI:Mpurecap} || !${MACHINE_ABI:Mbenchmark}
NEED_COMPAT=	64CB
.include <bsd.compat.mk>
.endif

.include "../tcpdump/Makefile"
