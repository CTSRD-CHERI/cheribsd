#	@(#)Makefile	8.2 (Berkeley) 2/3/94
# $FreeBSD$

SHLIBDIR?= /lib

.include <src.opts.mk>

LIBC_SRCTOP?= ${.CURDIR}/../libc

# Pick the current architecture directory for libc. In general, this is
# named MACHINE_CPUARCH, but some ABIs are different enough to require
# their own libc, so allow a directory named MACHINE_ARCH to override this.

.if exists(${LIBC_SRCTOP}/${MACHINE_ARCH})
LIBC_ARCH=${MACHINE_ARCH}
.else
LIBC_ARCH=${MACHINE_CPUARCH}
.endif

# All library objects contain FreeBSD revision strings by default; they may be
# excluded as a space-saving measure.  To produce a library that does
# not contain these strings, add -DSTRIP_FBSDID (see <sys/cdefs.h>) to CFLAGS
# below.  Note: there are no IDs for syscall stubs whose sources are generated.
# To include legacy CSRG sccsid strings, add -DLIBC_SCCS and -DSYSLIBC_SCCS
# to CFLAGS below.  -DSYSLIBC_SCCS affects just the system call stubs.
LIB=syscalls
SHLIB_MAJOR= 7
WARNS?=	2
CFLAGS+=-I${LIBC_SRCTOP}/include -I${LIBC_SRCTOP}/../../include
CFLAGS+=-I${LIBC_SRCTOP}/${LIBC_ARCH}
INSTALL_PIC_ARCHIVE=
PRECIOUSLIB=

# Define (empty) variables so that make doesn't give substitution
# errors if the included makefiles don't change these:
MDSRCS=
MISRCS=
MDASM=
MIASM=
NOASM=

LDFLAGS+=	-nodefaultlibs

.PATH:	${LIBC_SRCTOP}/gen
SRCS+=	getlogin.c

SYM_MAPS+=	${.CURDIR}/Symbol.map
SYM_MAPS+=	${LIBC_SRCTOP}/${LIBC_ARCH}/Symbol.map
.include "${.CURDIR}/Makefile.inc"

VERSION_DEF=${LIBC_SRCTOP}/Versions.def
SYMBOL_MAPS=${SYM_MAPS}
CFLAGS+= -DSYMBOL_VERSIONING

# If there are no machine dependent sources, append all the
# machine-independent sources:
.if empty(MDSRCS)
SRCS+=	${MISRCS}
.else
# Append machine-dependent sources, then append machine-independent sources
# for which there is no machine-dependent variant.
SRCS+=	${MDSRCS}
.for _src in ${MISRCS}
.if ${MDSRCS:R:M${_src:R}} == ""
SRCS+=	${_src}
.endif
.endfor
.endif

.include <bsd.lib.mk>
