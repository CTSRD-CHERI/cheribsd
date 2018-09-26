# $FreeBSD$

.include <src.opts.mk>

.if exists(${.CURDIR}/${MACHINE_ARCH})
SUBDIR+= ${MACHINE_ARCH}
.else
SUBDIR+= ${MACHINE_CPUARCH}
.endif

.if ${MACHINE_ARCH:Mmips*c*} || ${MK_CHERI} == "yes"
SUBDIR+=	libcheri
.endif

.include <bsd.subdir.mk>
