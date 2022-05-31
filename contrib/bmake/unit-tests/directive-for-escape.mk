# $NetBSD: directive-for-escape.mk,v 1.15 2022/01/27 20:15:14 rillig Exp $
#
# Test escaping of special characters in the iteration values of a .for loop.
# These values get expanded later using the :U variable modifier, and this
# escaping and unescaping must pass all characters and strings effectively
# unmodified.

.MAKEFLAGS: -df

# Even though the .for loops take quotes into account when splitting the
# string into words, the quotes don't need to be balanced, as of 2020-12-31.
# This could be considered a bug.
ASCII=	!"\#$$%&'()*+,-./0-9:;<=>?@A-Z[\]_^a-z{|}~

# XXX: As of 2020-12-31, the '#' is not preserved in the expanded body of
# the loop.  Not only would it need the escaping for the variable modifier
# ':U' but also the escaping for the line-end comment.
.for chars in ${ASCII}
.  info ${chars}
.endfor

# As of 2020-12-31, using 2 backslashes before be '#' would treat the '#'
# as comment character.  Using 3 backslashes doesn't help either since
# then the situation is essentially the same as with 1 backslash.
# This means that a '#' sign cannot be passed in the value of a .for loop
# at all.
ASCII.2020-12-31=	!"\\\#$$%&'()*+,-./0-9:;<=>?@A-Z[\]_^a-z{|}~
.for chars in ${ASCII.2020-12-31}
.  info ${chars}
.endfor

# Cover the code in ExprLen.
#
# XXX: It is unexpected that the variable V gets expanded in the loop body.
# The double '$$' should intuitively prevent exactly this.  Probably nobody
# was adventurous enough to use literal dollar signs in the values of a .for
# loop, allowing this edge case to go unnoticed for years.
#
# See for.c, function ExprLen.
V=		value
VALUES=		$$ $${V} $${V:=-with-modifier} $$(V) $$(V:=-with-modifier)
.for i in ${VALUES}
.  info $i
.endfor

# Try to cover the code for nested '{}' in ExprLen, without success.
#
# The value of the variable VALUES is not meant to be a variable expression.
# Instead, it is meant to represent literal text, the only escaping mechanism
# being that each '$' is written as '$$'.
#
# The .for loop splits ${VALUES} into 3 words, at the space characters, since
# the '$$' is an ordinary character and the spaces are not escaped.
#	Word 1 is '${UNDEF:U\$\$'
#	Word 2 is '{{}}'
#	Word 3 is 'end}'
# The first iteration expands the body of the .for loop to:
# expect: .  info ${:U\${UNDEF\:U\\$\\$}
# The modifier ':U' unescapes the '\$' to a simple '$'.
# The modifier ':U' unescapes the '\:' to a simple ':'.
# The modifier ':U' unescapes the '\\' to a simple '\'.
# The modifier ':U' resolves the expression '$\' to the word 'backslash', due
# to the following variable definition.
${:U\\}=	backslash
# FIXME: There was no expression '$\' in the original text of the previous
# line, that's a surprise in the parser.
# The modifier ':U' unescapes the '\$' to a simple '$'.
# expect+4: ${UNDEF:U\backslash$
VALUES=		$${UNDEF:U\$$\$$ {{}} end}
# XXX: Where in the code does the '\$\$' get converted into a single '\$'?
.for i in ${VALUES}
.  info $i
.endfor

# Second try to cover the code for nested '{}' in ExprLen.
#
# XXX: It is wrong that ExprLen requires the braces to be balanced.
# Each variable modifier has its own inconsistent way of parsing nested
# variable expressions, braces and parentheses.  (Compare ':M', ':S', and
# ':D' for details.)  The only sensible thing to do is therefore to let
# Var_Parse do all the parsing work.
VALUES=		begin<$${UNDEF:Ufallback:N{{{}}}}>end
.for i in ${VALUES}
.  info $i
.endfor

# A single trailing dollar doesn't happen in practice.
# The dollar sign is correctly passed through to the body of the .for loop.
# There, it is expanded by the .info directive, but even there a trailing
# dollar sign is kept as-is.
.for i in ${:U\$}
.  info ${i}
.endfor

# As of 2020-12-31, the name of the iteration variable can even contain
# colons, which then affects variable expressions having this exact modifier.
# This is clearly an unintended side effect of the implementation.
NUMBERS=	one two three
.for NUMBERS:M*e in replaced
.  info ${NUMBERS} ${NUMBERS:M*e}
.endfor

# As of 2020-12-31, the name of the iteration variable can contain braces,
# which gets even more surprising than colons, since it allows to replace
# sequences of variable expressions.  There is no practical use case for
# this, though.
BASENAME=	one
EXT=		.c
.for BASENAME}${EXT in replaced
.  info ${BASENAME}${EXT}
.endfor

# Demonstrate the various ways to refer to the iteration variable.
i=		outer
i2=		two
i,=		comma
.for i in inner
.  info .        $$i: $i
.  info .      $${i}: ${i}
.  info .   $${i:M*}: ${i:M*}
.  info .      $$(i): $(i)
.  info .   $$(i:M*): $(i:M*)
.  info . $${i$${:U}}: ${i${:U}}
.  info .    $${i\}}: ${i\}}	# XXX: unclear why ForLoop_SubstVarLong needs this
.  info .     $${i2}: ${i2}
.  info .     $${i,}: ${i,}
.  info .  adjacent: $i${i}${i:M*}$i
.endfor

# The variable name can be a single '$' since there is no check on valid
# variable names. ForLoop_SubstVarShort skips "stupid" variable names though,
# but ForLoop_SubstVarLong naively parses the body of the loop, substituting
# each '${$}' with an actual 'dollar'.
.for $ in dollar
.  info eight $$$$$$$$ and no cents.
.  info eight ${$}${$}${$}${$} and no cents.
.endfor
# Outside a .for loop, '${$}' is interpreted differently. The outer '$' starts
# a variable expression. The inner '$' is followed by a '}' and is thus a
# silent syntax error, the '$' is skipped. The variable name is thus '', and
# since since there is never a variable named '', the whole expression '${$}'
# evaluates to an empty string.
closing-brace=		}		# guard against an
${closing-brace}=	<closing-brace>	# alternative interpretation
.info eight ${$}${$}${$}${$} and no cents.

# What happens if the values from the .for loop contain a literal newline?
# Before for.c 1.144 from 2021-06-25, the newline was passed verbatim to the
# body of the .for loop, where it was then interpreted as a literal newline,
# leading to syntax errors such as "Unclosed variable expression" in the upper
# line and "Invalid line type" in the lower line.
.for i in "${.newline}"
.  info short: $i
.  info long: ${i}
.endfor

# No error since the newline character is not actually used.
.for i in "${.newline}"
.endfor

# Between for.c 1.161 from 2022-01-08 and before for.c 1.163 from 2022-01-09,
# a newline character in a .for loop led to a crash since at the point where
# the error message including the stack trace is printed, the body of the .for
# loop is assembled, and at that point, ForLoop.nextItem had already been
# advanced.
.MAKEFLAGS: -dp
.for i in "${.newline}"
: $i
.endfor
.MAKEFLAGS: -d0

.MAKEFLAGS: -df
.for i in \# \\\#
# $i
.endfor

.for i in $$ $$i $$(i) $${i} $$$$ $$$$$$$$ $${:U\$$\$$}
# $i
.endfor

# The expression '${.TARGET}' must be preserved as it is one of the 7 built-in
# target-local variables.  See for.c 1.45 from 2009-01-14.
.for i in ${.TARGET} $${.TARGET} $$${.TARGET} $$$${.TARGET}
# $i
.endfor
# expect: # ${:U${.TARGET}}
# XXX: Why does '$' result in the same text as '$$'?
# expect: # ${:U${.TARGET}}
# XXX: Why does the '$$' before the '${.TARGET}' lead to an escaped '}'?
# expect: # ${:U$${.TARGET\}}
# XXX: Why does '$' result in the same text as '$$'?
# XXX: Why does the '$$' before the '${.TARGET}' lead to an escaped '}'?
# expect: # ${:U$${.TARGET\}}

.for i in ((( {{{ ))) }}}
# $i
.endfor
.MAKEFLAGS: -d0

all:
