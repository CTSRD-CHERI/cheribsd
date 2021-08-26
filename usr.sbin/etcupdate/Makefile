# $FreeBSD$

.include <src.opts.mk>

SCRIPTS=etcupdate.sh
MAN=	etcupdate.8

# FIXME: These tests take a really long time to run on QEMU and are unlikely to
# catch any bugs in CheriBSD that don't also exist upstream. They are plain
# shell scripts so we can't use "atf_config_get include_slow_tests"
.if 0
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.endif

.include <bsd.prog.mk>
