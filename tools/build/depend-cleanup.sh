#!/bin/sh
#
# $FreeBSD$
#
# Our current make(1)-based approach to dependency tracking cannot cope with
# certain source tree changes, including:
# - removing source files
# - replacing generated files with files committed to the tree
# - changing file extensions (e.g. a C source file rewritten in C++)
#
# We handle those cases here in an ad-hoc fashion by looking for the known-
# bad case in the main .depend file, and if found deleting all of the related
# .depend files (including for example the lib32 version).
#
# These tests increase the build time (albeit by a small amount), so they
# should be removed once enough time has passed and it is extremely unlikely
# anyone would try a NO_CLEAN build against an object tree from before the
# related change.  One year should be sufficient.

OBJTOP=$1
if [ ! -d "$OBJTOP" ]; then
	echo "usage: $(basename $0) objtop" >&2
	exit 1
fi

if [ -z "${MACHINE+set}" ]; then
	echo "$(basename "$0"): MACHINE not set" >&2
	exit 1
fi

if [ -z "${MACHINE_ARCH+set}" ]; then
	echo "$(basename "$0"): MACHINE_ARCH not set" >&2
	exit 1
fi

# $1 directory
# $2 source filename w/o extension
# $3 source extension
_clean_dep()
{
	if egrep -qw "$2\.$3" "$OBJTOP"/$1/.depend.$2.*o 2>/dev/null; then
		echo "Removing stale dependencies and objects for $2.$3"
		rm -f \
		    "$OBJTOP"/$1/.depend.$2.* \
		    "$OBJTOP"/$1/$2.*o \
		    "$OBJTOP"/obj-lib64/$1/.depend.$2.* \
		    "$OBJTOP"/obj-lib64/$1/$2.*o \
		    "$OBJTOP"/obj-lib64c/$1/.depend.$2.* \
		    "$OBJTOP"/obj-lib64c/$1/$2.*o \
		    "$OBJTOP"/obj-lib32/$1/.depend.$2.* \
		    "$OBJTOP"/obj-lib32/$1/$2.*o
	fi
}

clean_dep()
{
	_clean_dep "$1" "$2" "$3"
	if [ "$1" == "lib/libc" ]; then
		_clean_dep lib/libc_c18n "$2" "$3"
	fi
}

# Date      Rev      Description
# 20200310  r358851  rename of openmp's ittnotify_static.c to .cpp
clean_dep lib/libomp ittnotify_static c
# 20200414  r359930  closefrom
clean_dep lib/libc   closefrom S
clean_dep lib/libsyscalls closefrom S

# 20200826  r364746  OpenZFS merge, apply a big hammer (remove whole tree)
if [ -e "$OBJTOP"/cddl/lib/libzfs/.depend.libzfs_changelist.o ] && \
    egrep -qw "cddl/contrib/opensolaris/lib/libzfs/common/libzfs_changelist.c" \
    "$OBJTOP"/cddl/lib/libzfs/.depend.libzfs_changelist.o; then
	echo "Removing old ZFS tree"
	rm -rf "$OBJTOP"/cddl "$OBJTOP"/obj-lib32/cddl \
	   "$OBJTOP"/obj-lib64/cddl "$OBJTOP"/obj-lib64c/cddl
fi

# 20200916  WARNS bumped, need bootstrapped crunchgen stubs
if [ -e "$OBJTOP"/rescue/rescue/rescue.c ] && \
    ! grep -q 'crunched_stub_t' "$OBJTOP"/rescue/rescue/rescue.c; then
	echo "Removing old rescue(8) tree"
	rm -rf "$OBJTOP"/rescue/rescue
fi

# 20210105  fda7daf06301   pfctl gained its own version of pf_ruleset.c
if [ -e "$OBJTOP"/sbin/pfctl/.depend.pf_ruleset.o ] && \
    egrep -qw "sys/netpfil/pf/pf_ruleset.c" \
    "$OBJTOP"/sbin/pfctl/.depend.pf_ruleset.o; then
	echo "Removing old pf_ruleset dependecy file"
	rm -rf "$OBJTOP"/sbin/pfctl/.depend.pf_ruleset.o
fi

# 20210108  821aa63a0940   non-widechar version of ncurses removed
if [ -e "$OBJTOP"/lib/ncurses/ncursesw ]; then
	echo "Removing stale ncurses objects"
	rm -rf "$OBJTOP"/lib/ncurses "$OBJTOP"/obj-lib32/lib/ncurses \
	   "$OBJTOP"/obj-lib64/lib/ncurses "$OBJTOP"/obj-lib64c/lib/ncurses
fi

# 20210608  f20893853e8e    move from atomic.S to atomic.c
clean_dep   cddl/lib/libspl atomic S
# 20211207  cbdec8db18b5    switch to libthr-friendly pdfork
clean_dep   lib/libc        pdfork S
clean_dep   lib/libsyscalls pdfork S

# 20211230  5e6a2d6eb220    libc++.so.1 path changed in ldscript
if [ -e "$OBJTOP"/lib/libc++/libc++.ld ] && \
    fgrep -q "/usr/lib/libc++.so" "$OBJTOP"/lib/libc++/libc++.ld; then
	echo "Removing old libc++ linker script"
	rm -f "$OBJTOP"/lib/libc++/libc++.ld
fi

# 20220326  fbc002cb72d2    move from bcmp.c to bcmp.S
if [ "$MACHINE_ARCH" = "amd64" ]; then
	clean_dep lib/libc bcmp c
fi

# 20220524  68fe988a40ca    kqueue_test binary replaced shell script
if stat "$OBJTOP"/tests/sys/kqueue/libkqueue/*kqtest* \
    "$OBJTOP"/tests/sys/kqueue/libkqueue/.depend.kqtest* >/dev/null 2>&1; then
	echo "Removing old kqtest"
	rm -f "$OBJTOP"/tests/sys/kqueue/libkqueue/.depend.* \
	   "$OBJTOP"/tests/sys/kqueue/libkqueue/*
fi

# 20221115  42d10b1b56f2    move from rs.c to rs.cc
clean_dep   usr.bin/rs      rs c

# 20230110  bc42155199b5    usr.sbin/zic/zic -> usr.sbin/zic
if [ -d "$OBJTOP"/usr.sbin/zic/zic ] ; then
	echo "Removing old zic directory"
	rm -rf "$OBJTOP"/usr.sbin/zic/zic
fi

# 20230208  29c5f8bf9a01    move from mkmakefile.c to mkmakefile.cc
clean_dep   usr.sbin/config  mkmakefile c
# 20230209  83d7ed8af3d9    convert to main.cc and mkoptions.cc
clean_dep   usr.sbin/config  main c
clean_dep   usr.sbin/config  mkoptions c

# 20230401  54579376c05e    kqueue1 from syscall to C wrapper
clean_dep   lib/libc        kqueue1 S
