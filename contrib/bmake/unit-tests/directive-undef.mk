# $NetBSD: directive-undef.mk,v 1.3 2020/08/23 19:30:13 rillig Exp $
#
# Tests for the .undef directive.

# As of 2020-07-28, .undef only undefines the first variable.
# All further variable names are silently ignored.
# See parse.c, string literal "undef".
1=		1
2=		2
3=		3
.undef 1 2 3
.if ${1:U_}${2:U_}${3:U_} != _23
.warning $1$2$3
.endif

all:
	@:;
