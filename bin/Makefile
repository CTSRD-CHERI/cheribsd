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
SUBDIR.${MK_LIBCHERI}+=	cheri_bench
.endif

# Small cheri programs
.if ${MACHINE_ABI:Mpurecap} || ${MK_COMPAT_CHERIABI} == "yes"
SUBDIR.${MK_CHERI}+=	cheri_minimal_dynamic_exe
SUBDIR.${MK_CHERI}+=	cheri_minimal_pie_exe
.if ${MACHINE} == "mips"
# mips assembly
SUBDIR.${MK_CHERI}+=	cheri_pthreads
.endif
SUBDIR.${MK_CHERI}+=	helloworld
.if ${MK_CXX} != "no"
SUBDIR.${MK_CHERI}+=	helloworld_cxx
.endif
SUBDIR.${MK_CHERI}+=	helloworld_static

# Consumers of libhelloworld
SUBDIR.${MK_LIBCHERI}+=	cheri_helloworld
SUBDIR.${MK_LIBCHERI}+=	cheriabi_helloworld

SUBDIR.${MK_CHERI}+=	cheribsdtest
.endif  # ${MACHINE_ABI:Mpurecap} || ${MK_COMPAT_CHERIABI} == "yes"


.include <bsd.arch.inc.mk>

SUBDIR.${MK_SENDMAIL}+=	rmail
SUBDIR.${MK_TCSH}+=	csh
SUBDIR.${MK_TESTS}+=	tests

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
