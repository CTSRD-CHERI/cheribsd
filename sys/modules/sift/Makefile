SYSDIR?=	${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

SUBDIR=		ace2 \
		ace2_syncpoint

.if ${MACHINE_CPU:Mcheri}
SUBDIR+=	scan_and_stash \
		scan_and_stash_ace \
		struct_access
.endif

.include <bsd.subdir.mk>
