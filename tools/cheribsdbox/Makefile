# A copy of bsdbox adjust to work for the CHERI FPGA
MAN=

.include <bsd.own.mk>
.include <src.opts.mk>

MK_SSP=	no

PROG=	cheribsdbox
CHERIBSDBOX_DIR?=	/bin
BINDIR?=${CHERIBSDBOX_DIR}
# We want to build all these tools as statically linked MIPS binaries to save size
WANT_CHERI=		none
CRUNCH_BUILDOPTS+=	WANT_CHERI=none

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

# XXXAR: do we really need clear?
SCRIPTS+= clear_FIXED
SCRIPTSNAME_clear_FIXED= clear
clear_FIXED: ../../usr.bin/tput/clear.sh
	sed '1s/\/bin\//\${CHERIBSDBOX_DIR}\//' ${.ALLSRC} > ${.TARGET}
CLEANFILES+= clear_FIXED

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
# ktrace:
CRUNCH_LIBS+=	-lsysdecode

# Avoid linking against libcasper for tcpdump/traceroute/kdump:
CRUNCH_BUILDOPTS_tcpdump= -DWITHOUT_CASPER MK_CASPER=no
CRUNCH_BUILDOPTS_traceroute= -DWITHOUT_CASPER MK_CASPER=no
CRUNCH_BUILDOPTS_traceroute6= -DWITHOUT_CASPER MK_CASPER=no
CRUNCH_BUILDOPTS_kdump= -DWITHOUT_CASPER MK_CASPER=no

# login/su (could theoretically use static_libpam but that will probably not work)
CRUNCH_SHLIBS+= -lpam -lbsm

# needed by ifconfig
CRUNCH_LIBS+=	-l80211
# needed by fetch:
CRUNCH_LIBS+= -lfetch
# devinfo
CRUNCH_LIBS+= -ldevinfo
# usbconfig
CRUNCH_LIBS+= -lusb

# netstat needs libkvm (which needs libelf)
CRUNCH_LIBS+= -lkvm -lelf -lmemstat -lnetgraph

# Misc libs copied from recue/bsdbox:
CRUNCH_LIBS+= -ledit -ll -ltermcapw

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
		dd \
		df \
		expr \
		hostname \
		kenv \
		ln \
		ls \
		mkdir \
		mv \
		ps \
		realpath \
		rm \
		rmdir \
		sh \
		sleep \
		stty \
		test

CRUNCH_ALIAS_test=	[
CRUNCH_BUILDTOOLS+=	bin/sh
CRUNCH_ALIAS_sh=	-sh

# TODO: tcsh and csh?

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
		ping6 \
		rcorder \
		reboot \
		route \
		rtsol \
		shutdown \
		sysctl \
		umount
CRUNCH_ALIAS_md5=	sha256

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
		basename \
		bzip2 \
		dirname \
		fetch \
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
		login \
		mktemp \
		nc \
		netstat \
		passwd \
		sed \
		seq \
		sockstat \
		su \
		tail \
		tee \
		tftp \
		time \
		top \
		tput \
		tr \
		uname \
		uudecode \
		uuencode \
		vmstat \
		w \
		xargs

CRUNCH_ALIAS_bzip2= bunzip2
CRUNCH_ALIAS_hexdump= hd od
CRUNCH_ALIAS_w= uptime


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
CRUNCH_PROGS_usr.bin+= vi
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
		usbconfig \
		watch

# TODO: (not sure how to make this work because -lnetbsd is marked as internallib
# so it will give a linker error
# TODO: maybe just add the c files needed from libnetbsd?
# Or maybe we don't actually need mtree which would be even better
# CRUNCH_SRCDIRS+=nmtree
# CRUNCH_ALIAS_nmtree= mtree
# CRUNCH_LIBS+= -lnetbsd

# usr/sbin/de4ctl
# usr/sbin/flashit
# usr/sbin/vipw

# TODO: ctsrd/usr.sbin/mtlctl?

# TODO: do we need ctsrd/bin/wr?


##################################################################

CRUNCH_SRCDIRS+= libexec
CRUNCH_PROGS_libexec+=	getty
# from sshd: usr/libexec/sftp-server



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

cheribsdbox.mtree: Makefile
	echo '#mtree 2.0' > ${.TARGET}
.for D in ${CRUNCH_SRCDIRS}
.if empty(INSTALLDIR_${D}) || empty(LINKPATH_${D})
.error "empty(INSTALLDIR_${D}) || empty(LINKPATH_${D})"
.endif
.for P in ${CRUNCH_PROGS_${D}}
.ifndef CRUNCH_SUPPRESS_LINK_${P}
	#echo ".${INSTALLDIR_${D}}/${P} type=link uname=root gname=wheel mode=0755 link=${LINKPATH_${D}}" >> ${.TARGET}
	echo ".${INSTALLDIR_${D}}/${P} type=file uname=root gname=wheel mode=0755 contents=./${BINDIR}/${PROG}" >> ${.TARGET}
.endif
.for A in ${CRUNCH_ALIAS_${P}}
.ifndef CRUNCH_SUPPRESS_LINK_${A}
	#echo ".${INSTALLDIR_${D}}/${A} type=link uname=root gname=wheel mode=0755 link=${P}" >> ${.TARGET}
	echo ".${INSTALLDIR_${D}}/${A} type=file uname=root gname=wheel mode=0755 contents=./${BINDIR}/${PROG}" >> ${.TARGET}
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

# the crunchgen build environment
.include <bsd.crunchgen.mk>

# and since it creates a program..
.include <bsd.prog.mk>
