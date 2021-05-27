.include <src.opts.mk>
MK_SSP=	no

LIB=syscalls

LIBC_SRCTOP=	${.CURDIR}/../libc/

.if exists(${LIBC_SRCTOP}/${MACHINE_ARCH})
LIBC_ARCH=${MACHINE_ARCH}
.else
LIBC_ARCH=${MACHINE_CPUARCH}
.endif

SHLIB_MAJOR= 7

CFLAGS+=-I${LIBC_SRCTOP}/include -I${LIBC_SRCTOP}/../../include
CFLAGS+=-I${LIBC_SRCTOP}/${LIBC_ARCH}

# Define (empty) variables so that make doesn't give substitution
# errors if the included makefiles don't change these:
MDSRCS=
MISRCS=
MDASM=
MIASM=
NOASM=

.include "${LIBC_SRCTOP}/sys/Makefile.inc"
SRCS:=	${SRCS:Nbrk.c:Nshm_open.c:Nclosefrom.c:Ncosetup.c:Ncoaccept.c:Ncocall.c:Ncogetpid2.c:Ncogettid.c:S/__vdso_gettc.c/trivial-vdso_tc.c/}

.PATH:	${LIBC_SRCTOP}/gen
# We don't really need these:
#SRCS+=	_spinlock_stub.c \
#	__pthread_mutex_init_calloc_cb_stub.c
# But we do need errno
SRCS+=	errno.c
CFLAGS.interposing_table.c+=	-DINTERPOS_SYSCALLS_ONLY=1

# We also need memcpy for binuptime's use of a bintime. Compile a copy of the
# generic libc version, which should stop it interfering with anyone else and
# allow us to get an optimised version if we have a libc at run time (or link
# time in the case of the static library).
.PATH:	${LIBC_SRCTOP}/string
SRCS+=	memcpy.c
CFLAGS.memcpy.c+=	-DIN_LIBSYSCALLS -Wno-cast-align

SYMBOL_MAPS=	${SYM_MAPS}
VERSION_DEF=	${LIBC_SRCTOP}/Versions.def
CFLAGS+= -DSYMBOL_VERSIONING

MAN=
MLINKS=

SOLINKOPTS+=	-Wl.-undefined=report-all -Wl,-no-undefined
LDFLAGS+=	-nostdlib -nodefaultlibs

.include <bsd.lib.mk>
