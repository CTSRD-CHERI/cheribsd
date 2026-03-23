TESTSDIR=		${TESTSBASE}/sys/kern/tty
BINDIR=			${TESTSDIR}

PLAIN_TESTS_PORCH+=	test_canon
PLAIN_TESTS_PORCH+=	test_canon_fullbuf
PLAIN_TESTS_PORCH+=	test_ncanon
PLAIN_TESTS_PORCH+=	test_recanon
PLAIN_TESTS_C+=		tiocnotty

PROGS+=			fionread
PROGS+=			readsz

.include <bsd.test.mk>
