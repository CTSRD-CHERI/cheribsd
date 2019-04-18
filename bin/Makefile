#	From: @(#)Makefile	8.1 (Berkeley) 5/31/93
# $FreeBSD$

.include <src.opts.mk>

SUBDIR= cat \
	chflags \
	chio \
	chmod \
	cp \
	date \
	dd \
	df \
	domainname \
	echo \
	ed \
	expr \
	freebsd-version \
	getfacl \
	hostname \
	kenv \
	kill \
	ln \
	ls \
	mkdir \
	mv \
	pax \
	pkill \
	ps \
	pwait \
	pwd \
	realpath \
	rm \
	rmdir \
	setfacl \
	sh \
	sleep \
	stty \
	sync \
	test \
	uuidgen

.if ${TARGET} == "mips"
SUBDIR+=	shmem_bench
SUBDIR+=	cheri_bench
.endif

SUBDIR.${MK_CHERI}+=	cheri_helloworld
SUBDIR.${MK_CHERI}+=	cheri_pthreads
SUBDIR.${MK_CHERI}+=	cheriabitest
SUBDIR.${MK_CHERI}+=	cheriabitest-mt
SUBDIR.${MK_CHERI}+=	cheritest
SUBDIR.${MK_CHERI}+=	cheritest-mt
SUBDIR.${MK_CHERI}+=	helloworld
SUBDIR.${MK_CHERI}+=	helloworld_static
SUBDIR.${MK_CHERI}+=	helloworld_cxx

SUBDIR.${MK_SENDMAIL}+=	rmail
SUBDIR.${MK_TCSH}+=	csh
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_CHERI_SHARED} != "no"
SUBDIR.${MK_CHERI}+=	cheri_minimal_dynamic_exe
SUBDIR.${MK_CHERI}+=	cheri_minimal_pie_exe
SUBDIR.${MK_CHERI}+=	cheriabitest-dynamic
SUBDIR.${MK_CHERI}+=	cheriabitest-dynamic-mt
SUBDIR.${MK_CHERI}+=	cheritest-dynamic
SUBDIR.${MK_CHERI}+=	cheritest-dynamic-mt
.endif

.include <bsd.arch.inc.mk>

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
