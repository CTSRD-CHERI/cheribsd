# $FreeBSD$
#
# Option file for src builds.
#
# Users define WITH_FOO and WITHOUT_FOO on the command line or in /etc/src.conf
# and /etc/make.conf files. These translate in the build system to MK_FOO={yes,no}
# with (usually) sensible defaults.
#
# Makefiles must include bsd.opts.mk after defining specific MK_FOO options that
# are applicable for that Makefile (typically there are none, but sometimes there
# are exceptions). Recursive makes usually add MK_FOO=no for options that they wish
# to omit from that make.
#
# Makefiles must include bsd.mkopt.mk before they test the value of any MK_FOO
# variable.
#
# Makefiles may also assume that this file is included by bsd.own.mk should it
# need variables defined there prior to the end of the Makefile where
# bsd.{subdir,lib.bin}.mk is traditionally included.
#
# The old-style YES_FOO and NO_FOO are being phased out. No new instances of them
# should be added. Old instances should be removed since they were just to
# bridge the gap between FreeBSD 4 and FreeBSD 5.
#
# Makefiles should never test WITH_FOO or WITHOUT_FOO directly (although an
# exception is made for _WITHOUT_SRCONF which turns off this mechanism
# completely).
#

.if !target(__<bsd.opts.mk>__)
__<bsd.opts.mk>__:

.if !defined(_WITHOUT_SRCCONF)
#
# Define MK_* variables (which are either "yes" or "no") for users
# to set via WITH_*/WITHOUT_* in /etc/src.conf and override in the
# make(1) environment.
# These should be tested with `== "no"' or `!= "no"' in makefiles.
# The NO_* variables should only be set by makefiles for variables
# that haven't been converted over.
#

# Only these options are used by bsd.*.mk. KERBEROS and OPENSSH are
# unfortunately needed to support statically linking the entire
# tree. su(1) wouldn't link since it depends on PAM which depends on
# ssh libraries when building with OPENSSH, and likewise for KERBEROS.

# All other variables used to build /usr/src live in src.opts.mk
# and variables from both files are documented in src.conf(5).

__DEFAULT_YES_OPTIONS = \
    ASSERT_DEBUG \
    DEBUG_FILES \
    DOCCOMPRESS \
    INCLUDES \
    INSTALLLIB \
    KERBEROS \
    MAKE_CHECK_USE_SANDBOX \
    MAN \
    MANCOMPRESS \
    NIS \
    NLS \
    OPENSSH \
    PIE \
    PROFILE \
    SSP \
    TESTS \
    TOOLCHAIN \
    WARNS \
    WERROR

__DEFAULT_NO_OPTIONS = \
    BIND_NOW \
    CCACHE_BUILD \
    CTF \
    INIT_ALL_PATTERN \
    INIT_ALL_ZERO \
    INSTALL_AS_USER \
    RETPOLINE \
    STALE_STAGED

__DEFAULT_NO_OPTIONS+= \
    CHERI_CAPREVOKE \
    CHERI_PURE \
    CHERI \
    DLMALLOC \
    DEMO_VULNERABILITIES

__DEFAULT_DEPENDENT_OPTIONS = \
    MAKE_CHECK_USE_SANDBOX/TESTS \
    STAGING_MAN/STAGING \
    STAGING_PROG/STAGING \
    STALE_STAGED/STAGING \

#
# Default behaviour of some options depends on the architecture.  Unfortunately
# this means that we have to test TARGET_ARCH (the buildworld case) as well
# as MACHINE_ARCH (the non-buildworld case).  Normally TARGET_ARCH is not
# used at all in bsd.*.mk, but we have to make an exception here if we want
# to allow defaults for some things like clang to vary by target architecture.
# Additional, per-target behavior should be rarely added only after much
# gnashing of teeth and grinding of gears.
#
.if defined(TARGET_ARCH)
__T=${TARGET_ARCH}
.else
__T=${MACHINE_ARCH}
.endif
.if defined(TARGET)
__TT=${TARGET}
.else
__TT=${MACHINE}
.endif

.if !defined(WITH_CHERI) && defined(WITH_CHERI128)
.if defined(WITHOUT_CHERI)
.error WITHOUT_CHERI and WITH_CHERI128 makes no sense
.endif
.warning WITH_CHERI128 is obsolete, use WITH_CHERI instead.
WITH_CHERI:=	yes
.endif

.include <bsd.mkopt.mk>

.if ${__TT:Mmips*} && ${MK_CHERI} == "yes"
MK_CLANG:=	no
.endif

.if ${MK_INIT_ALL_PATTERN} == "yes" && ${MK_INIT_ALL_ZERO} == "yes"
.warning WITH_INIT_ALL_PATTERN and WITH_INIT_ALL_ZERO are mutually exclusive.
.endif

#
# Supported NO_* options (if defined, MK_* will be forced to "no",
# regardless of user's setting).
#
# These are transitional and will disappaer in the FreeBSD 12.
#
.for var in \
    CTF \
    DEBUG_FILES \
    INSTALLLIB \
    MAN \
    PROFILE \
    WARNS \
    WERROR
.if defined(NO_${var})
.error "NO_${var} is defined, but deprecated. Please use MK_${var}=no instead."
MK_${var}:=no
.endif
.endfor

.include <bsd.cpu.mk>

.endif # !_WITHOUT_SRCCONF

.endif
