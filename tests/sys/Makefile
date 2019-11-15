# $FreeBSD$

.include <src.opts.mk>

TESTSDIR=		${TESTSBASE}/sys

TESTS_SUBDIRS+=		acl
TESTS_SUBDIRS+=		aio
TESTS_SUBDIRS+=		${_audit}
TESTS_SUBDIRS+=		auditpipe
TESTS_SUBDIRS+=		capsicum
TESTS_SUBDIRS+=		${_cddl}
TESTS_SUBDIRS+=		devrandom
TESTS_SUBDIRS+=		fifo
TESTS_SUBDIRS+=		file
TESTS_SUBDIRS+=		fs
TESTS_SUBDIRS+=		geom
TESTS_SUBDIRS+=		kern
TESTS_SUBDIRS+=		kqueue
TESTS_SUBDIRS+=		mac
TESTS_SUBDIRS+=		mqueue
TESTS_SUBDIRS+=		netinet
TESTS_SUBDIRS+=		netinet6
TESTS_SUBDIRS+=		netipsec
TESTS_SUBDIRS+=		netmap
TESTS_SUBDIRS+=		netpfil
TESTS_SUBDIRS+=		opencrypto
TESTS_SUBDIRS+=		posixshm
TESTS_SUBDIRS+=		sys
TESTS_SUBDIRS+=		vfs
TESTS_SUBDIRS+=		vm


# XXXAR: the audit tests are flaky when running on QEMU CHERI and often time out
# during cleanup. They start and stop a new auditd for every test CASE which
# takes a really long time on QEMU. In the latest jenkins run these tests took
# 9.5 hours to run! Skip them until we can run them at a reasonable speed.
.if ${MK_AUDIT} != "no" && ${MK_CHERI} == "no"
_audit=	audit
.endif

.if ${MK_CDDL} != "no"
_cddl=	cddl
.endif

# Items not integrated into kyua runs by default
SUBDIR+=		pjdfstest

SUBDIR+=		common

.include <bsd.test.mk>
