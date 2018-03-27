# $FreeBSD$

SHLIB_MAJOR?=	11

.include "../Makefile.inc"

.if defined(LIBCHERI) && !empty(CHERI_USE_CAP_TABLE) && ${MK_CHERI256} == "yes"
# For shared libraries it is fine since each of them has it's own table but
# when statically linking sshd we are slightly over the limit:
# added 18093 entries to .cap_table but current maximum is 16384; try recompiling non-performance critical source files with -mllvm -mxcaptable
# TODO: since the _CHERI_CAPABILITY_TABLE_ symbol still points to the start of
# the .cap_table section we are wasting 50% of the immediate space.
# If it pointed to the start this would not be necessary
# TODO: would it make sense to have clc scale by cap size instead of always by 16
STATIC_CFLAGS+=-mllvm -mxcaptable
.endif
