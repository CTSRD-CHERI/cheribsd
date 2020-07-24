NO_SHARED=	yes
LIB?=	freebsd
TOOLS_CROSSBUILD_DIR=${SRCTOP}/tools/build/cross-build
LIBFREEBSD_DIR=${TOOLS_CROSSBUILD_DIR}/libfreebsd
.PATH: ${TOOLS_CROSSBUILD_DIR}/libfreebsd

INCSGROUPS?=	INCS SYSINCS
SYSINCSDIR?=	${INCLUDEDIR}/sys

INCS+=	${SRCTOP}/include/mpool.h \
		${SRCTOP}/include/ndbm.h
INCS+=	${SRCTOP}/include/err.h \
		${SRCTOP}/include/stringlist.h
SYSINCS+=	${SRCTOP}/sys/sys/queue.h

SYSINCS+=	${SRCTOP}/sys/sys/md5.h
SYSINCS+=	${SRCTOP}/sys/sys/sbuf.h
SYSINCS+=	${SRCTOP}/sys/sys/elf32.h
SYSINCS+=	${SRCTOP}/sys/sys/elf64.h
SYSINCS+=	${SRCTOP}/sys/sys/elf_common.h
SYSINCS+=	${SRCTOP}/sys/sys/elf_generic.h
SYSINCS+=	${SRCTOP}/sys/sys/tree.h

_host_arch=${MACHINE}
.if ${_host_arch} == "x86_64"
# bmake on Linux/mac often prints that instead of amd64
_host_arch=amd64
.endif
.if ${_host_arch} == "unknown"
# HACK: If MACHINE is unknown, assume we are building on x86
_host_arch=amd64
.endif
MACHINESYSINCS+=	${SRCTOP}/sys/${_host_arch}/include/elf.h
.if ${_host_arch} == "amd64" || ${_host_arch} == "i386"
X86INCS+=	${SRCTOP}/sys/x86/include/elf.h
.endif

# needed for btxld:
MACHINESYSINCS+=	${SRCTOP}/sys/${_host_arch}/include/exec.h
MACHINESYSINCS+=	${SRCTOP}/sys/${_host_arch}/include/reloc.h
INCS+=	${SRCTOP}/include/a.out.h
INCS+=	${SRCTOP}/include/nlist.h
SYSINCS+=	${SRCTOP}/sys/sys/imgact_aout.h
SYSINCS+=	${SRCTOP}/sys/sys/nlist_aout.h

# For mkscrfil.c:
SYSINCS+=	${SRCTOP}/sys/sys/consio.h

# for gencat:
INCS+=	${SRCTOP}/include/nl_types.h

# for vtfontcvt:
SYSINCS+=	${SRCTOP}/sys/sys/fnv_hash.h

# opensolaris stuff
INCS+=	${SRCTOP}/include/elf.h



# Note: ${LIBC_SRCTOP}/db.h is explicitly not added here so that all cross-tools
# include ../include/common/db.h instead (which defines dbopen to __freebsd_dbopen)

MK_SYMVER=	no
LIBC_SRCTOP=	${SRCTOP}/lib/libc/
.include "${LIBC_SRCTOP}/db/Makefile.inc"

# dbopen behaves differently on Linux and FreeBSD -> namespace the symbols
# to ensure that we get linker errors if libfreebsd isn't linked.
CFLAGS+=	-I ${TOOLS_CROSSBUILD_DIR}/libc-bootstrap -Ddbopen=__freebsd_dbopen
INCS+=	${LIBFREEBSD_DIR}/db.h

# Do the same as we did for dbopen() for getopt() on since it's not compatible
# on Linux (and to avoid surprises also compile the FreeBSD code on macOS
.PATH: ${SRCTOP}/lib/libc/stdlib
SRCS+=	getopt.c getopt_long.c

# for cap_mkdb:
.PATH: ${LIBC_SRCTOP}/gen
SRCS+=	getcap.c
# or setmode,getmode
SRCS+=	setmode.c
# the sl_* functions are also not available in glibc
SRCS+=	stringlist.c


# strtonum and rpmatch are not available on Linux
.PATH: ${SRCTOP}/lib/libc/stdlib
SRCS+=	strtonum.c merge.c heapsort.c
# linux also doesn't have reallocf
SRCS+=	reallocf.c
.PATH: ${SRCTOP}/lib/libc/locale
SRCS+=	rpmatch.c

.if ${.MAKE.OS} == "Linux"
# On Linux, glibc does not provide strlcpy,strlcat or strmode
.PATH: ${SRCTOP}/lib/libc/string
SRCS+=	strlcpy.c strlcat.c strmode.c
# include fgetln/fgetwln fallback from libbsd:
SRCS+=	fgetln_fallback.c fgetwln_fallback.c
# glibc doesn't provide getprogname()
SRCS+=	progname.c
# Also warnc and the arc4random functions are missing on Linux
.PATH: ${SRCTOP}/lib/libc/gen
SRCS+=	arc4random.c arc4random_uniform.c err.c
CFLAGS.arc4random.c+=	-I${SRCTOP}/sys/crypto/chacha20
SRCS+=	closefrom.c
CFLAGS.closefrom.c+=	-DSTDC_HEADERS -DHAVE_SYS_DIR_H -DHAVE_DIRENT_H \
	-DHAVE_DIRFD -DHAVE_SYSCONF
.endif

# expand_number is not provided by either Linux or MacOS libutil
.PATH: ${SRCTOP}/lib/libutil
SRCS+=	expand_number.c
# Linux libutil also doesn't have fparseln
SRCS+=	fparseln.c

# for tzsetup:
SRCS+=	fake_sysctl.c


# capsicum support
SYSINCS+=	${SRCTOP}/sys/sys/capsicum.h
SYSINCS+=	${SRCTOP}/sys/sys/caprights.h
SRCS+=	capsicum_stubs.c
# XXX: we can't add ${SRCTOP}/sys/kern to .PATH since that will causes
# conflicts with other files. Instead create a symlink to subr_capability
# in the source tree
subr_capability.c: ${SRCTOP}/sys/kern/subr_capability.c
	cp ${.ALLSRC} ${.TARGET}
CLEANFILES+=	subr_capability.c
SRCS+=		subr_capability.c
