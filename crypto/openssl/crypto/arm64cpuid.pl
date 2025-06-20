#! /usr/bin/env perl
# Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

$code.=<<___;
#include "arm_arch.h"

.text
.arch_extension	crypto

.align	5
.globl	_armv7_neon_probe
.type	_armv7_neon_probe,%function
_armv7_neon_probe:
	AARCH64_VALID_CALL_TARGET
	orr	v15.16b, v15.16b, v15.16b
	ret
.size	_armv7_neon_probe,.-_armv7_neon_probe

.globl	_armv7_tick
.type	_armv7_tick,%function
_armv7_tick:
	AARCH64_VALID_CALL_TARGET
#ifdef	__APPLE__
	mrs	x0, CNTPCT_EL0
#else
	mrs	x0, CNTVCT_EL0
#endif
	ret
.size	_armv7_tick,.-_armv7_tick

.globl	_armv8_aes_probe
.type	_armv8_aes_probe,%function
_armv8_aes_probe:
	AARCH64_VALID_CALL_TARGET
	aese	v0.16b, v0.16b
	ret
.size	_armv8_aes_probe,.-_armv8_aes_probe

.globl	_armv8_sha1_probe
.type	_armv8_sha1_probe,%function
_armv8_sha1_probe:
	AARCH64_VALID_CALL_TARGET
	sha1h	s0, s0
	ret
.size	_armv8_sha1_probe,.-_armv8_sha1_probe

.globl	_armv8_sha256_probe
.type	_armv8_sha256_probe,%function
_armv8_sha256_probe:
	AARCH64_VALID_CALL_TARGET
	sha256su0	v0.4s, v0.4s
	ret
.size	_armv8_sha256_probe,.-_armv8_sha256_probe

.globl	_armv8_pmull_probe
.type	_armv8_pmull_probe,%function
_armv8_pmull_probe:
	AARCH64_VALID_CALL_TARGET
	pmull	v0.1q, v0.1d, v0.1d
	ret
.size	_armv8_pmull_probe,.-_armv8_pmull_probe

.globl	_armv8_sha512_probe
.type	_armv8_sha512_probe,%function
_armv8_sha512_probe:
	AARCH64_VALID_CALL_TARGET
	.long	0xcec08000	// sha512su0	v0.2d,v0.2d
	ret
.size	_armv8_sha512_probe,.-_armv8_sha512_probe

.globl	_armv8_cpuid_probe
.type	_armv8_cpuid_probe,%function
_armv8_cpuid_probe:
	AARCH64_VALID_CALL_TARGET
	mrs	x0, midr_el1
	ret
.size	_armv8_cpuid_probe,.-_armv8_cpuid_probe

.globl	OPENSSL_cleanse
.type	OPENSSL_cleanse,%function
.align	5
OPENSSL_cleanse:
	AARCH64_VALID_CALL_TARGET
	cbz	x1,.Lret	// len==0?
	cmp	x1,#15
	b.hi	.Lot		// len>15
	nop
.Little:
	strb	wzr,[PTR(0)],#1	// store byte-by-byte
	subs	x1,x1,#1
	b.ne	.Little
.Lret:	ret

.align	4
.Lot:	tst	x0,#7
	b.eq	.Laligned	// inp is aligned
	strb	wzr,[PTR(0)],#1	// store byte-by-byte
	sub	x1,x1,#1
	b	.Lot

.align	4
.Laligned:
	str	xzr,[PTR(0)],#8	// store word-by-word
	sub	x1,x1,#8
	tst	x1,#-8
	b.ne	.Laligned	// len>=8
	cbnz	x1,.Little	// len!=0?
	ret
.size	OPENSSL_cleanse,.-OPENSSL_cleanse

.globl	CRYPTO_memcmp
.type	CRYPTO_memcmp,%function
.align	4
CRYPTO_memcmp:
	AARCH64_VALID_CALL_TARGET
	eor	w3,w3,w3
	cbz	x2,.Lno_data	// len==0?
	cmp	x2,#16
	b.ne	.Loop_cmp
	ldp	x8,x9,[PTR(0)]
	ldp	x10,x11,[PTR(1)]
	eor	x8,x8,x10
	eor	x9,x9,x11
	orr	x8,x8,x9
	mov	x0,#1
	cmp	x8,#0
	csel	x0,xzr,x0,eq
	ret

.align	4
.Loop_cmp:
	ldrb	w4,[PTR(0)],#1
	ldrb	w5,[PTR(1)],#1
	eor	w4,w4,w5
	orr	w3,w3,w4
	subs	x2,x2,#1
	b.ne	.Loop_cmp

.Lno_data:
	neg	w0,w3
	lsr	w0,w0,#31
	ret
.size	CRYPTO_memcmp,.-CRYPTO_memcmp
___

print $code;
close STDOUT or die "error closing STDOUT: $!";
