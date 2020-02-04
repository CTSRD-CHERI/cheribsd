# $FreeBSD$

.PATH: ${.CURDIR}/../../include

LIB=		egacy
SRC=
INCSGROUPS=	INCS SYSINCS CASPERINC UFSINCS FFSINCS MSDOSFSINCS DISKINCS
INCSGROUPS+=	MACHINESYSINCS X86INCS RPCINCS
INCS=

SYSINCSDIR=	${INCLUDEDIR}/sys
CASPERINCDIR=	${INCLUDEDIR}/casper
# Also add ufs/ffs/msdosfs/disk headers to allow building makefs as a bootstrap tool
UFSINCSDIR=	${INCLUDEDIR}/ufs/ufs
FFSINCSDIR=	${INCLUDEDIR}/ufs/ffs
MSDOSFSINCSDIR=	${INCLUDEDIR}/fs/msdosfs
DISKINCSDIR=	${INCLUDEDIR}/sys/disk
MACHINESYSINCSDIR=	${INCLUDEDIR}/machine
X86INCSDIR=	${INCLUDEDIR}/x86

BOOTSTRAPPING?=	0


.if ${.MAKE.OS} == "Darwin"
_XCODE_ROOT!=xcode-select -p
# since macOS 10.14 C headers are no longer installed in /usr but only
# provided via the SDK
.if ${_XCODE_ROOT} == "/Library/Developer/CommandLineTools"
# Only command line tools installed -> host headers are in the SDKs directory
_MACOS_SDK_DIR=${_XCODE_ROOT}/SDKs/MacOSX.sdk/
.else
# Full XCode installed -> host headers are below Platforms/MacOSX.platform
_MACOS_SDK_DIR=${_XCODE_ROOT}/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
.endif
HOST_INCLUDE_ROOT=${_MACOS_SDK_DIR}/usr/include
.if !exists(${HOST_INCLUDE_ROOT}/stdio.h)
.error "You must install the macOS SDK (try xcode-select --install)"
.endif
.else
HOST_INCLUDE_ROOT=/usr/include
.endif

_WITH_PWCACHEDB!= grep -c pwcache_groupdb ${HOST_INCLUDE_ROOT}/grp.h || true
.if ${_WITH_PWCACHEDB} == 0
.PATH: ${.CURDIR}/../../contrib/libc-pwcache
CFLAGS.pwcache.c+=	-I${.CURDIR}/../../contrib/libc-pwcache
CFLAGS.pwcache.c+=	-I${.CURDIR}/cross-build/libc-bootstrap
SRCS+=		pwcache.c
.endif

_WITH_STRSVIS!=	grep -c strsvis ${HOST_INCLUDE_ROOT}/vis.h 2>/dev/null || true
.if ${_WITH_STRSVIS} == 0
.PATH: ${.CURDIR}/../../contrib/libc-vis
INCS+=		vis.h
SRCS+=		vis.c unvis.c
CFLAGS.vis.c+=	-I${.CURDIR}/../../contrib/libc-vis -I${.CURDIR}/cross-build/libc-bootstrap
CFLAGS.unvis.c+=	-I${.CURDIR}/../../contrib/libc-vis -I${.CURDIR}/cross-build/libc-bootstrap
.endif

_WITH_REALLOCARRAY!= grep -c reallocarray ${HOST_INCLUDE_ROOT}/stdlib.h || true
.if ${_WITH_REALLOCARRAY} == 0
.PATH: ${.CURDIR}/../../lib/libc/stdlib
INCS+=		stdlib.h
SRCS+=		reallocarray.c
CFLAGS.reallocarray.c+=	-I${.CURDIR}/cross-build/libc-bootstrap
.endif

_WITH_UTIMENS!= grep -c utimensat ${HOST_INCLUDE_ROOT}/sys/stat.h || true
.if ${_WITH_UTIMENS} == 0
SYSINCS+=	stat.h
SRCS+=		futimens.c utimensat.c
.endif

_WITH_NO_SUBOBJECT_BOUNDS!= grep -c __no_subobject_bounds ${HOST_INCLUDE_ROOT}/sys/cdefs.h || true
.if ${_WITH_NO_SUBOBJECT_BOUNDS} == 0
SYSINCS+=	cdefs.h
.endif

_WITH_EXPLICIT_BZERO!= grep -c explicit_bzero ${HOST_INCLUDE_ROOT}/strings.h || true
.if ${_WITH_EXPLICIT_BZERO} == 0
# .PATH: ${SRCTOP}/sys/libkern
# Adding sys/libkern to .PATH breaks building the cross-build compat library
# since that attempts to build strlcpy.c from libc and adding libkern here will
# cause it to pick the file from libkern instead (which won't compile).
# Avoid modifying .PATH by creating a copy in the build directory instead.
explicit_bzero.c: ${SRCTOP}/sys/libkern/explicit_bzero.c
	cp ${.ALLSRC} ${.TARGET}
CLEANFILES+=	explicit_bzero.c
INCS+=		strings.h
SRCS+=		explicit_bzero.c
.endif

.if exists(${HOST_INCLUDE_ROOT}/capsicum_helpers.h)
_WITH_CAPH_ENTER!= grep -c caph_enter ${HOST_INCLUDE_ROOT}/capsicum_helpers.h || true
_WITH_CAPH_RIGHTS_LIMIT!= grep -c caph_rights_limit ${HOST_INCLUDE_ROOT}/capsicum_helpers.h || true
.endif
.if !defined(_WITH_CAPH_ENTER) || ${_WITH_CAPH_ENTER} == 0 || ${_WITH_CAPH_RIGHTS_LIMIT} == 0
.PATH: ${SRCTOP}/lib/libcapsicum
INCS+=		capsicum_helpers.h
.PATH: ${SRCTOP}/lib/libcasper/libcasper
INCS+=		libcasper.h
.endif

# rpcgen should build against the source tree rpc/types.h and not the host.
# This is especially important on non-FreeBSD systems where the types may
# not match.
# TODO: should this be done only for non-FreeBSD?
RPCINCSDIR=	${INCLUDEDIR}/rpc
RPCINCS+=	${SRCTOP}/sys/rpc/types.h

.if ${.MAKE.OS} != "FreeBSD"
# don't copy stdlib.h when cross-building since it will cause
# conflicts with the host system's headers
INCS:=	${INCS:Nstdlib.h}
.include "cross-build/libfreebsd/Makefile.inc"
.endif

CASPERINC+=	${SRCTOP}/lib/libcasper/services/cap_fileargs/cap_fileargs.h

.if empty(SRCS)
SRCS=		dummy.c
.endif

.if defined(CROSS_BUILD_TESTING)
SUBDIR+=		cross-build
.endif

# To allow bootstrapping makefs on FreeBSD 11 or non-FreeBSD systems:
UFSINCS+=	${SRCTOP}/sys/ufs/ufs/dinode.h
UFSINCS+=	${SRCTOP}/sys/ufs/ufs/dir.h
FFSINCS+=	${SRCTOP}/sys/ufs/ffs/fs.h

MSDOSFSINCS+=	${SRCTOP}/sys/fs/msdosfs/bootsect.h
MSDOSFSINCS+=	${SRCTOP}/sys/fs/msdosfs/bpb.h
MSDOSFSINCS+=	${SRCTOP}/sys/fs/msdosfs/denode.h
MSDOSFSINCS+=	${SRCTOP}/sys/fs/msdosfs/direntry.h
MSDOSFSINCS+=	${SRCTOP}/sys/fs/msdosfs/fat.h
MSDOSFSINCS+=	${SRCTOP}/sys/fs/msdosfs/msdosfsmount.h
DISKINCS+=	${SRCTOP}/sys/sys/disk/bsd.h

# Needed to build config (since it uses libnv)
SYSINCS+=	${SRCTOP}/sys/sys/nv.h ${SRCTOP}/sys/sys/cnv.h \
		${SRCTOP}/sys/sys/dnv.h

# We want to run the build with only ${WORLDTMP} in $PATH to ensure we don't
# accidentally run tools that are incompatible but happen to be in $PATH.
# This is especially important when building on Linux/MacOS where many of the
# programs used during the build accept different flags or generate different
# output. On those platforms we only symlink the tools known to be compatible
# (e.g. basic utilities such as mkdir) into ${WORLDTMP} and build all others
# from the FreeBSD sources during the bootstrap-tools stage.

# basic commands: It is fine to use the host version for all of these even on
# Linux/MacOS since we only use flags that are supported by all of them.
_host_tools_to_symlink=	basename bzip2 bunzip2 chmod chown cmp comm cp date dd \
	dirname echo env false find fmt gzip gunzip head hostname id ln ls \
	mkdir mv nice patch rm sh sleep stat tee touch tr true uname \
	uniq wc which

.include <src.opts.mk>

.if ${MK_BOOT} != "no"
# xz/unxz is used by EFI
_host_tools_to_symlink+=xz unxz
.endif

# We also need a symlink to the absolute path to the make binary used for
# the toplevel makefile. This is not necessarily the same as `which make`
# since e.g. on Linux and MacOS that will be GNU make.
_make_abs!=	which "${MAKE}"
_host_abs_tools_to_symlink=	${_make_abs}:make ${_make_abs}:bmake

.if ${.MAKE.OS} != "FreeBSD"
# can we bootstrap this instead?
.if ${MK_GCC} != "no" && ${MK_CXX} != "no"
_host_tools_to_symlink+=gperf
.endif

_py3_abs=${PYTHON3_BINARY}
.if empty(_py3_abs)
_py3_abs!=	which python3 2>/dev/null || echo "/invalid/path/to/python3"
.if !exists(${_py3_abs})
# Fall back to /usr/local/bin/python3 (macOS) if /usr/local/bin is not in $PATH
# or fail the build if that doesn't exist either
_py3_abs=/usr/local/bin/python3
.endif
.endif
.if empty(_py3_abs) || !exists(${_py3_abs})
.error "Could not determine path to python3. Please set PYTHON3_BINARY"
.endif
_host_abs_tools_to_symlink+=	${_py3_abs}:python3

_make_abs!=	which "${MAKE}"
_host_abs_tools_to_symlink+=	${_make_abs}:make ${_make_abs}:bmake
.if ${.MAKE.OS} == "Darwin"
# /usr/bin/cpp may invoke xcrun:
_host_tools_to_symlink+=xcrun
.endif  # ${.MAKE.OS} == "Darwin"
# On Ubuntu /bin/sh is dash which is totally useless. Let's just link bash
# as the build sh since that will work fine.
_host_abs_tools_to_symlink+=	/bin/bash:sh
_host_tools_to_symlink:=${_host_tools_to_symlink:Nsh}
.endif

host-symlinks:
	@echo "Linking host tools into ${DESTDIR}/bin"
.for _tool in ${_host_tools_to_symlink}
	@if [ ! -e "${DESTDIR}/bin/${_tool}" ]; then \
		source_path=`which ${_tool} || true`; \
		if [ ! -e "$${source_path}" ] ; then \
			echo "Cannot find host tool '${_tool}'" >&2; false; \
		fi; \
		ln -sfnv "$${source_path}" "${DESTDIR}/bin/${_tool}"; \
	fi
.endfor
.for _tool in ${_host_abs_tools_to_symlink}
	@source_path="${_tool:S/:/ /:[1]}"; \
	target_path="${DESTDIR}/bin/${_tool:S/:/ /:[2]}"; \
	if [ ! -e "$${target_path}" ] ; then \
		if [ ! -e "$${source_path}" ] ; then \
			echo "Host tool '${src_path}' is missing"; false; \
		fi; \
		ln -sfnv "$${source_path}" "$${target_path}"; \
	fi
.endfor

# Create all the directories that are needed during the legacy, bootstrap-tools
# and cross-tools stages. We do this here using mkdir since mtree may not exist
# yet (this happens if we are crossbuilding from Linux/Mac).
INSTALLDIR_LIST= \
	bin \
	lib/casper \
	lib/geom \
	usr/include/casper \
	usr/include/private/zstd \
	usr/lib \
	usr/libexec

installdirs:
	mkdir -p ${INSTALLDIR_LIST:S,^,${DESTDIR}/,}

# Link usr/bin, sbin, and usr/sbin to bin so that it doesn't matter whether a
# bootstrap tool was added to WORLTMP with a symlink or by building it in the
# bootstrap-tools phase. We could also overrride BINDIR when building bootstrap
# tools but adding the symlinks is easier and means all tools are also
# in the directory that they are installed to normally.

.for _dir in sbin usr/sbin usr/bin
# delete existing directories from before r340157
	@if [ -e ${DESTDIR}/${_dir} ] && [ ! -L ${DESTDIR}/${_dir} ]; then \
	    echo "removing old non-symlink ${DESTDIR}/${_dir}"; \
	    rm -rf "${DESTDIR}/${_dir}"; \
	fi
.endfor
	ln -sfn bin ${DESTDIR}/sbin
	ln -sfn ../bin ${DESTDIR}/usr/bin
	ln -sfn ../bin ${DESTDIR}/usr/sbin
.for _group in ${INCSGROUPS:NINCS}
	mkdir -p "${DESTDIR}/${${_group}DIR}"
.endfor

.include <bsd.lib.mk>
