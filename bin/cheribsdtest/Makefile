# $FreeBSD$

.include <src.opts.mk>

.if !${MACHINE_ABI:Mpurecap} || ${MK_LIB64} == "yes"
SUBDIR+=	hybrid \
		hybrid-dynamic \
		hybrid-dynamic-mt \
		hybrid-mt
.endif

.if ${MACHINE_ABI:Mpurecap} || ${MK_LIB64C} == "yes"
SUBDIR+=	purecap \
		purecap-dynamic \
		purecap-dynamic-mt \
		purecap-mt

.if ${MACHINE_CPUARCH} == "aarch64" && ${MK_LIB64C} == "no"
SUBDIR+=	mt-c18n
.endif
.endif

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
