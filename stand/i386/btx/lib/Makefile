# $FreeBSD$

.include <bsd.init.mk>
.include <bsd.linker.mk>

PROG=	crt0.o
INTERNALPROG=
SRCS=	btxcsu.S btxsys.S btxv86.S
CFLAGS+=-I${BOOTSRC}/i386/common
LDFLAGS+=-Wl,-r
# XXX: -r is incompatible with --gdb-index, so pretend that ld doesn't
# support --gdb-index to avoid a linker error.
LINKER_FEATURES:=${LINKER_FEATURES:Ngdb-index}

.include <bsd.prog.mk>
