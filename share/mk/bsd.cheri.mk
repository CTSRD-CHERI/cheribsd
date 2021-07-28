#-
# Copyright (c) 2015, 2016 (SRI International)
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

.if defined(__BSD_PROG_MK)
.if ${MK_CHERI_PURE} == "yes" && !defined(TESTSDIR)
WANT_CHERI?=	pure
.endif
.endif

.if defined(NEED_COMPAT) && ${NEED_COMPAT:MCHERI}
NEED_CHERI=	pure
.endif

.if ${MACHINE_ARCH:Mmips*} && (!${MACHINE_ARCH:Mmips*c*} || defined(COMPAT_CHERI))
.if !${.TARGETS:Mbuild-tools} && !defined(BOOTSTRAPPING)
.if defined(NEED_CHERI)
.if ${MK_CHERI} == "no"
.error NEED_CHERI defined, but CHERI is not enabled (MACHINE_ARCH=${MACHINE_ARCH})
.endif
.if ${NEED_CHERI} != "hybrid" && ${NEED_CHERI} != "pure"
.error NEED_CHERI must be 'hybrid' or 'pure'
.endif
WANT_CHERI:= ${NEED_CHERI}
.endif

.if ${MK_CHERI} != "no" && defined(WANT_CHERI) && ${WANT_CHERI} != "none"

.if ${WANT_CHERI} == "pure"
MIPS_ABI:=	purecap
STATIC_CFLAGS+=	-ftls-model=local-exec

.ifdef NO_WERROR
# Implicit function declarations should always be an error in purecap mode as
# we will probably generate wrong code for calling them
CFLAGS+=-Werror=implicit-function-declaration
.endif
.else
STATIC_CFLAGS+= -ftls-model=local-exec # MIPS/hybrid case
.endif

.endif
.endif
.endif
