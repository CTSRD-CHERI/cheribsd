# A copy of bsdbox adjust to work for the CHERI FPGA
MAN=

.include <bsd.own.mk>
.include <src.opts.mk>

MK_SSP=	no
MK_PIE=	no

PROG=	cheribsdbox
CHERIBSDBOX_DIR?=	/bin
BINDIR?=${CHERIBSDBOX_DIR}

# We want to build all these tools as statically linked binaries, but for MIPS
# we don't want to build this as purecap yet since it generates a captable that
# is too large to link.
.if ${MACHINE_ARCH:Mmips64*} && ${MK_LIB64} == "yes"
NEED_COMPAT=	64
CRUNCH_BUILDOPTS+=	NEED_COMPAT=64
CRUNCH_OBJTOP=		${OBJTOP}/obj-lib64
.endif
CRUNCH_OBJTOP?=		${OBJTOP}
CRUNCH_BUILDOPTS+=	-DWITHOUT_TESTS MK_TESTS=no -D_CRUNCHGEN
# Avoid linking against libcasper for tcpdump/traceroute/kdump:
CRUNCH_BUILDOPTS+=	-DWITHOUT_CASPER MK_CASPER=no
# Try to reduce size by avoiding locale support
CRUNCH_BUILDOPTS+=	-DWITHOUT_LOCALES MK_LOCALES=no
# Disable kerberos support
CRUNCH_BUILDOPTS+=	MK_KERBEROS=no MK_KERBEROS_SUPPORT=no MK_GSSAPI=no
# Smaller PAM:
CRUNCH_BUILDOPTS+=	MK_RADIUS_SUPPORT=no
# Smaller SSH
CRUNCH_BUILDOPTS+=	MK_LDNS_UTILS=no MK_LDNS=no
# Avoid redundant libs
CRUNCH_BUILDOPTS+=	MK_PROFILE=no
# Avoid dependency on audit
CRUNCH_BUILDOPTS+=	MK_AUDIT=no



# Do not do hardlinks as part of the install since we want to be able to install
# this without conflicting with the real binaries and instead do some mtree
# magic to generate a sensible image
CRUNCH_GENERATE_LINKS= no

# Define Makefile variable RESCUE
CRUNCH_BUILDOPTS+= -DRESCUE

# Which sources have local-arch build tools?
# Define as blank; others need to override
CRUNCH_BUILDTOOLS=


.if 0  # we can just add  the original scripts to the list of needed files
# Shell scripts need #! line to be edited from /bin/sh to /rescue/sh
SCRIPTS+= dhclient_FIXED
SCRIPTSNAME_dhclient_FIXED= dhclient-script
dhclient_FIXED: ../../sbin/dhclient/dhclient-script
	sed '1s/\/bin\//\${CHERIBSDBOX_DIR}\//' ${.ALLSRC} > ${.TARGET}
CLEANFILES+= dhclient_FIXED

# Similarly for nextboot:
SCRIPTS= nextboot_FIXED
SCRIPTSNAME_nextboot_FIXED= nextboot
nextboot_FIXED: ../../sbin/reboot/nextboot.sh
	sed '1s/\/bin\//\${CHERIBSDBOX_DIR}\//' ${.ALLSRC} > ${.TARGET}
CLEANFILES+= nextboot_FIXED
.endif

# Libraries:
# We install sshd so we need a shared libcrypto and libc anyway
# Similarly for libutil, etc we can link shared to save space
# We need libcrypto anyway for sshd and it's massive so don't embed it here
CRUNCH_SHLIBS+= -lcrypto -lssl
CRUNCH_SHLIBS+=	-lc -lutil -lcrypt -lxo
# libm is also needed by other tools so let's link dynamically
CRUNCH_SHLIBS+=	-lm
# libz is needed by libprivatessh so we might as well link dynamically
CRUNCH_SHLIBS+=	-lz


# grep/tar/xz
CRUNCH_LIBS+=	-llzma
CRUNCH_LIBS+=	-larchive -lprivatezstd
CRUNCH_SHLIBS+=	-pthread

# ktrace/truss:
CRUNCH_LIBS+=	-lsysdecode

# needed by ifconfig
CRUNCH_LIBS+=	-l80211
CRUNCH_LIBS+=		${CRUNCH_OBJTOP}/lib/libifconfig/libifconfig.a
CRUNCH_BUILDOPTS+=	CRUNCH_CFLAGS+=-I${CRUNCH_OBJTOP}/lib/libifconfig
# needed by fetch:
CRUNCH_LIBS+= -lfetch
# devinfo
CRUNCH_LIBS+= -ldevinfo
# usbconfig
.if ${MK_USB} != "no"
CRUNCH_LIBS+= -lusb
.endif

# netstat needs libkvm (which needs libelf)
CRUNCH_SHLIBS+=	-lkvm -lelf -lprocstat
CRUNCH_LIBS+=	-lmemstat
# avoid depending on -lnetgraph
CRUNCH_BUILDOPTS_netstat+=MK_NETGRAPH_SUPPORT=no -j1


# Misc libs copied from recue/bsdbox:
CRUNCH_LIBS+= -ledit -ltermcapw

###################################################################
# Programs from stock /bin
#
# WARNING: Changing this list may require adjusting
# /usr/include/paths.h as well!  You were warned!
#
CRUNCH_SRCDIRS+= bin
CRUNCH_PROGS_bin+=	cat \
		chflags \
		chmod \
		cp \
		date \
		dd \
		df \
		echo \
		expr \
		hostname \
		kenv \
		kill \
		ln \
		ls \
		mkdir \
		mv \
		ps \
		pwd \
		realpath \
		rm \
		rmdir \
		sleep \
		stty \
		test \
		uuidgen

CRUNCH_ALIAS_test=	[

# Su needs latest crunchgen to work with cheribsdbox sh/csh because it sets argv[0]
# and then cheribsdbox thinks it should execute _su
CRUNCH_BUILDTOOLS+=	bin/sh
CRUNCH_PROGS_bin+=	sh
CRUNCH_ALIAS_sh=	-sh

CRUNCH_BUILDTOOLS+=	bin/csh
CRUNCH_PROGS_bin+=	csh
CRUNCH_ALIAS_csh=	-csh tcsh -tcsh
# to exclude csh/sh:
# CRUNCH_SUPPRESS_LINK_sh=	1
# CRUNCH_SUPPRESS_LINK_csh=	1


###################################################################
# Programs from standard /sbin
#
# WARNING: Changing this list may require adjusting
# /usr/include/paths.h as well!  You were warned!
#
# Note that mdmfs have their own private 'pathnames.h'
# headers in addition to the standard 'paths.h' header.
#
CRUNCH_SRCDIRS+= sbin

CRUNCH_LIBS+= -lalias -lcam -lcursesw -ldevstat -lipsec
# Don't forget this - ifconfig, etc -adrian
CRUNCH_LIBS+= -lgeom -lbsdxml -ljail -lkiconv -lmd -lsbuf -lufs
# Needed for wireguard support in ifconfig
CRUNCH_LIBS+= -lnv


CRUNCH_PROGS_sbin+= dhclient \
		dmesg \
		dumpfs \
		ifconfig \
		md5 \
		mount \
		mount_msdosfs \
		mount_nfs \
		newfs \
		ping \
		rcorder \
		reboot \
		route \
		rtsol \
		shutdown \
		sysctl \
		umount
CRUNCH_ALIAS_md5=	sha256
CRUNCH_ALIAS_shutdown= poweroff

# TODO: add init once the image works fine:
# CRUNCH_PROGS_sbin+= init


# TODO: do we need these:
# sbin/fsck
# sbin/fsck_ufs
# sbin/fsdb
# sbin/kldload
# sbin/kldstat
# sbin/kldunload
# sbin/mdconfig
# sbin/mdmfs
# sbin/mount_mfs

# devd won't work with crunchgen
# sbin/devd



##################################################################
# Programs from stock /usr/bin
#
CRUNCH_SRCDIRS+= usr.bin
# grep
CRUNCH_LIBS+=	-lbz2

CRUNCH_PROGS_usr.bin+= \
		awk \
		basename \
		bintrans \
		bmake \
		bzip2 \
		cpuset \
		diff \
		dirname \
		du \
		env \
		false \
		fetch \
		find \
		fsync \
		grep \
		head \
		hexdump \
		id \
		jot \
		kdump \
		ktrace \
		ldd \
		less \
		limits \
		locale \
		login \
		mktemp \
		nc \
		passwd \
		procstat \
		resizewin \
		sed \
		seq \
		sockstat \
		sort \
		stat \
		tail \
		tar \
		tee \
		tftp \
		time \
		timeout \
		top \
		touch \
		tr \
		true \
		truss \
		uname \
		vmstat \
		w \
		wall \
		which \
		xargs

CRUNCH_BUILDTOOLS+=	usr.bin/awk

CRUNCH_ALIAS_bintrans=	uuencode b64encode uudecode b64decode base64
CRUNCH_ALIAS_bmake=	make
CRUNCH_ALIAS_bzip2=	bunzip2
CRUNCH_ALIAS_tar=	bsdtar
CRUNCH_ALIAS_stat=	realink
CRUNCH_ALIAS_hexdump=	hd od
CRUNCH_ALIAS_w=	uptime
CRUNCH_PROGS_usr.bin+=su

# Tracing currently only implemented for CHERI-QEMU architectures
.if ${MACHINE} == "mips" || ${MACHINE} == "riscv"
CRUNCH_PROGS_usr.bin+=	qtrace
.endif
.if ${MACHINE_ARCH:Mmips64*} || ${MACHINE_ARCH:Mriscv64*}
CRUNCH_PROGS_usr.bin+=	minimal_count_stats
.if ${MACHINE_ARCH:Mmips64*}
# backwards compat for old benchmark scripts
CRUNCH_ALIAS_minimal_count_stats= beri_count_stats
.endif
.endif


# FIXME: wait -> usr.bin/alias (but that is just a script so how to add
.if 0
LINKS=	${BINDIR}/alias ${BINDIR}/bg \
	${BINDIR}/alias ${BINDIR}/cd \
	${BINDIR}/alias ${BINDIR}/command \
	${BINDIR}/alias ${BINDIR}/fc \
	${BINDIR}/alias ${BINDIR}/fg \
	${BINDIR}/alias ${BINDIR}/getopts \
	${BINDIR}/alias ${BINDIR}/hash \
	${BINDIR}/alias ${BINDIR}/jobs \
	${BINDIR}/alias ${BINDIR}/read \
	${BINDIR}/alias ${BINDIR}/type \
	${BINDIR}/alias ${BINDIR}/ulimit \
	${BINDIR}/alias ${BINDIR}/umask \
	${BINDIR}/alias ${BINDIR}/unalias \
	${BINDIR}/alias ${BINDIR}/wait
.endif

.if ${MK_VI} != "no"
# let's see if vi also works
CRUNCH_BUILDTOOLS+=	usr.bin/vi/catalog
CRUNCH_PROGS_usr.bin+= vi
CRUNCH_LIBS+= -lncursesw_real
.endif

CRUNCH_ALIAS_id= groups whoami
CRUNCH_ALIAS_less= more

# TODO: These are in /usr/bin but probably won't work
# scp sftp ssh ssh-keygen

##################################################################
# Programs from stock /usr/sbin
#
CRUNCH_SRCDIRS+= usr.sbin
CRUNCH_PROGS_usr.sbin+= \
		chown \
		devctl \
		devinfo \
		diskinfo \
		iostat \
		ip6addrctl \
		mtest \
		ndp \
		newsyslog \
		pw \
		pwd_mkdb \
		syslogd \
		tcpdump \
		traceroute \
		traceroute6 \
		watch

.if ${MK_USB} != "no"
CRUNCH_PROGS_usr.sbin+= \
		usbconfig
.endif


# Also build mount_smb for QEMU user-mode smb shares:
CRUNCH_PROGS_usr.sbin+=	mount_smbfs
CRUNCH_LIBS+=	-lsmb

# required for devctl
CRUNCH_LIBS+=	-ldevctl

# Build mtree as well:
CRUNCH_PROGS_usr.sbin+=	nmtree
CRUNCH_ALIAS_nmtree= mtree
# TODO: Not sure what the correct way of doing this is because -lnetbsd is
# marked as internallib so -lnetbsd will give a linker error
# It seems like ${LIBNETBSD} works:
CRUNCH_LIBS+=	${LIBNETBSD}

# usr/sbin/vipw






##################################################################

CRUNCH_SRCDIRS+= libexec
CRUNCH_PROGS_libexec+=	getty
# from sshd: usr/libexec/sftp-server


##### sshd, ssh, scp: #####
# TODO: should we build a separate binary for these programs?

CRUNCH_SRCDIRS+= secure/usr.sbin
CRUNCH_PROGS_secure/usr.sbin+=	sshd
CRUNCH_SHLIBS+=	-lpam -lutil

CRUNCH_SRCDIRS+= secure/usr.bin
CRUNCH_PROGS_secure/usr.bin+=	scp sftp ssh ssh-keygen

CRUNCH_SRCDIRS+= secure/libexec
CRUNCH_PROGS_secure/libexec+=	sftp-server

# Disable all optional SSH features to make sshd,scp,ssh as small as possible
DISABLE_OPTIONAL_SSH_FEATURES+=	\
	MK_AUDIT=no \
	MK_BLACKLIST_SUPPORT=no \
	MK_TCP_WRAPPERS=no
# Kerberos support uses up way too much space on our minimal images:
# so let's build sshd without it
DISABLE_OPTIONAL_SSH_FEATURES+=MK_KERBEROS_SUPPORT=no
# TODO: would be nice to add CRUNCH_BUILDOPTS+=	MK_LDNS=no
# However, libprivatessh links against ldns so we can't skip it

CRUNCH_BUILDOPTS_sshd+=${DISABLE_OPTIONAL_SSH_FEATURES}
CRUNCH_BUILDOPTS_scp+=${DISABLE_OPTIONAL_SSH_FEATURES}
CRUNCH_BUILDOPTS_ssh+=${DISABLE_OPTIONAL_SSH_FEATURES}
CRUNCH_BUILDOPTS_ssh-keygen+=${DISABLE_OPTIONAL_SSH_FEATURES}
CRUNCH_BUILDOPTS_sftp-server+=${DISABLE_OPTIONAL_SSH_FEATURES}


### END programs ####

# Generate an mtree file to be used when building the FPGA images
# I'm not sure how to add hardlinks to makefs without actually writing the
# hardlinks. The problem is that we want to install the original programs to
# the rootfs but replace them with links to cheribsdbox on the FPGA memory fs
# image. It seems to me like the easiest way to do this is to just write an
# mtree manifest with symlinks. Since crunchgen should only be checking argv[0]
# this should also work fine

FILES=cheribsdbox.mtree
FILESDIR=/

# Example entry for symlinks::
# ./usr/bin/chfn type=link uname=root gname=wheel mode=0755 link=chpass tags=package=runtime
INSTALLDIR_bin=/bin
LINKPATH_bin:=${PROG}
INSTALLDIR_sbin=/sbin
LINKPATH_sbin:=../${PROG}
INSTALLDIR_usr.bin=/usr/bin
LINKPATH_usr.bin:=../../${PROG}
INSTALLDIR_usr.sbin=/usr/sbin
LINKPATH_usr.sbin:=../../${PROG}
INSTALLDIR_libexec=/usr/libexec
LINKPATH_libexec:=../../${PROG}
INSTALLDIR_secure/usr.sbin=/usr/sbin
LINKPATH_secure/usr.sbin:=../../${PROG}
INSTALLDIR_secure/usr.bin=/usr/bin
LINKPATH_secure/usr.bin:=../../${PROG}
INSTALLDIR_secure/libexec=/usr/libexec
LINKPATH_secure/libexec:=../../${PROG}

cheribsdbox.mtree: Makefile
	echo '#mtree 2.0' > ${.TARGET}
.for D in ${CRUNCH_SRCDIRS}
.if empty(INSTALLDIR_${D}) || empty(LINKPATH_${D})
.error "empty(INSTALLDIR_${D}) || empty(LINKPATH_${D})"
.endif
.for P in ${CRUNCH_PROGS_${D}}
.ifndef CRUNCH_SUPPRESS_LINK_${P}
	#echo ".${INSTALLDIR_${D}}/${P} type=link uname=root gname=wheel mode=0755 link=${LINKPATH_${D}}" >> ${.TARGET}
	echo ".${INSTALLDIR_${D}}/${P} type=file uname=root gname=wheel mode=0755 contents=.${BINDIR}/${PROG}" >> ${.TARGET}
.endif
.for A in ${CRUNCH_ALIAS_${P}}
.ifndef CRUNCH_SUPPRESS_LINK_${A}
	#echo ".${INSTALLDIR_${D}}/${A} type=link uname=root gname=wheel mode=0755 link=${P}" >> ${.TARGET}
	echo ".${INSTALLDIR_${D}}/${A} type=file uname=root gname=wheel mode=0755 contents=.${BINDIR}/${PROG}" >> ${.TARGET}
.endif
.endfor
.endfor
.endfor
	@echo "cheribsdbox manifest written"

# Work around makefs stupidity:
# Check for hardlinks. If the contents key is used, then the check
# will only trigger if the contents file is a link even if it is used
# by more than one file
# -> we need to create at last one hardlink to cheribsdbox
LINKS+=${BINDIR}/${PROG} ${BINDIR}/${PROG}.dummy-hardlink-for-makefs

check_crunchgen:
	if [ "`which crunchgen`" = "/usr/bin/crunchgen" ]; then \
	    echo "Should not be using crunchgen from /usr/bin!"; false; \
	fi
all: check_crunchgen

.if defined(NO_RTLD) || defined(NO_SHARED)
# Force empty shlibs if we are building without RTLD/NO_SHARED
# See top_makefile_rules(FILE *outmk) in crunchgen.c
CRUNCH_LIBS:=${CRUNCH_LIBS} ${CRUNCH_SHLIBS} -Wl,--verbose -v
.undef CRUNCH_SHLIBS
# TODO: CRUNCH_BUILDOPTS+=-DNO_SHARED
.endif

# Also build a version of libssh without optional deps
CRUNCH_CUSTOM_LIBS+=secure/lib/libssh
CRUNCH_BUILDOPTS_secure/lib/libssh+="SSHDIR=${SRCTOP}/crypto/openssh"
CRUNCH_LIBS+=-lprivatessh

# the crunchgen build environment
.include <bsd.crunchgen.mk>

.include <bsd.compat.mk>
# and since it creates a program..
.include <bsd.prog.mk>
