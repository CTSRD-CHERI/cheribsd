# $FreeBSD$

.include <src.opts.mk>

SUBDIR=
SUBDIR.${MK_DIALOG}+=	libdialog
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_GNU_GREP} != "no" || ${MK_GNU_GREP_COMPAT} != "no" || \
    ${MK_GDB} != "no"
SUBDIR+=		libregex
.endif

.if ${MACHINE_ARCH:Mmips*c*}
# Don't use csu for CheriABI
SUBDIR:=	${SUBDIR:Ncsu}
# We'll be using the libunwind based libgcc_eh and libgcc_eh when the time
# comes.
SUBDIR:=	${SUBDIR:Nlibgcc}
.endif

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
