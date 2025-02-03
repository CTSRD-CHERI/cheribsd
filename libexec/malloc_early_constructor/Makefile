.include <src.opts.mk>

SUBDIR=		purecap \
		purecap-dynamic \
		purecap-dynamic-mt \
		purecap-mt

.if ${MACHINE_ABI:Mpurecap} || ${MK_LIB64C} == "yes"
.if ${MACHINE_CPUARCH} == "aarch64"
SUBDIR+=	mt-c18n
.endif
.endif

.if (${MACHINE_ABI:Mpurecap} && ${MACHINE_ABI:Mbenchmark}) || ${MK_LIB64CB} == "yes"
SUBDIR+=	purecap-benchmark \
		purecap-benchmark-dynamic \
		purecap-benchmark-dynamic-mt \
		purecap-benchmark-mt
.endif

.include <bsd.subdir.mk>
