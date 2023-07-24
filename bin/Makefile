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
	nproc \
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
	timeout \
	uuidgen

# Small cheri programs
.if ${MACHINE_ABI:Mpurecap} || ${MK_LIB64C} == "yes"
SUBDIR+= \
	cheri_minimal_dynamic_exe \
	cheri_minimal_pie_exe \
	cheribsdtest \
	helloworld \
	helloworld_cxx \
	helloworld_static
.endif  # ${MACHINE_ABI:Mpurecap} || ${MK_LIB64C} == "yes"


.include <bsd.arch.inc.mk>

SUBDIR.${MK_SENDMAIL}+=	rmail
SUBDIR.${MK_TCSH}+=	csh
SUBDIR.${MK_TESTS}+=	tests

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
