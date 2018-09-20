# $FreeBSD$

.PATH:		${SRCTOP}/tests
KYUAFILE=	yes

.if ! ${MACHINE_ARCH:Mmips64*}
# test-programs require C++ support so disable for CHERI
SUBDIR=		test-programs
.endif

.include <bsd.test.mk>
