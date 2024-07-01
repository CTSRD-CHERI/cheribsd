SHLIB=	cheribsdtest_dynamic
PRIVATELIB=
MAN=	# No manpage; this is internal.

SRCS=	cheribsdtest_dynamic_fptr.c					\
	cheribsdtest_dynamic_identity_cap.c

.if ${MACHINE_CPUARCH} == "aarch64"
SRCS+=	cheribsdtest_dynamic_ifunc.c
.endif

.include <bsd.lib.mk>
