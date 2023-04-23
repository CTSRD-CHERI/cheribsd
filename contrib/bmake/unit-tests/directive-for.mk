# $NetBSD: directive-for.mk,v 1.15 2022/10/01 09:23:04 rillig Exp $
#
# Tests for the .for directive.
#
# TODO: Describe naming conventions for the loop variables.
#	.for f in values
#	.for file in values
#	.for _FILE_ in values
#	.for .FILE. in values
#	.for _f_ in values

# Using the .for loop, lists of values can be produced.
# In simple cases, the :@var@${var}@ variable modifier can be used to
# achieve the same effects.
#
.undef NUMBERS
.for num in 1 2 3
NUMBERS+=	${num}
.endfor
.if ${NUMBERS} != "1 2 3"
.  error
.endif

# The .for loop also works for multiple iteration variables.
# This is something that the variable modifier :@ cannot do.
.for name value in VARNAME value NAME2 value2
${name}=	${value}
.endfor
.if ${VARNAME} != "value" || ${NAME2} != "value2"
.  error
.endif

# The .for loop splits the items at whitespace, taking quotes into account,
# just like the :M or :S variable modifiers.
#
# Until 2012-06-03, it had split the items exactly at whitespace, without
# taking the quotes into account.  This had resulted in 10 words.
#
.undef WORDS
.for var in one t\ w\ o "three three" 'four four' `five six`
WORDS+=	counted
.endfor
.if ${WORDS:[#]} != 6
.  error
.endif

# In the body of the .for loop, the iteration variables can be accessed
# like normal variables, even though they are not really variables.
#
# Instead, the expression ${var} is transformed into ${:U1}, ${:U2} and so
# on, before the loop body is evaluated.
#
# A notable effect of this implementation technique is that the .for
# iteration variables and the normal global variables live in separate
# namespaces and do not influence each other.
#
var=	value before
var2=	value before
.for var var2 in 1 2 3 4
.endfor
.if ${var} != "value before"
.  warning After the .for loop, var must still have its original value.
.endif
.if ${var2} != "value before"
.  warning After the .for loop, var2 must still have its original value.
.endif

# Everything from the paragraph above also applies if the loop body is
# empty, even if there is no actual iteration since the loop items are
# also empty.
#
var=	value before
var2=	value before
.for var var2 in ${:U}
.endfor
.if ${var} != "value before"
.  warning After the .for loop, var must still have its original value.
.endif
.if ${var2} != "value before"
.  warning After the .for loop, var2 must still have its original value.
.endif

# Until 2008-12-21, the values of the iteration variables were simply
# inserted as plain text and then parsed as usual, which made it possible
# to achieve all kinds of strange effects.
#
# Before that date, the .for loop expanded to:
#	EXPANSION+= value
# Since that date, the .for loop expands to:
#	EXPANSION${:U+}= value
#
EXPANSION=		before
EXPANSION+ =		before
.for plus in +
EXPANSION${plus}=	value
.endfor
.if ${EXPANSION} != "before"
.  error This must be a make from before 2009.
.endif
.if ${EXPANSION+} != "value"
.  error This must be a make from before 2009.
.endif

# When the outer .for loop is expanded, it sees the expression ${i} and
# expands it.  The inner loop then has nothing more to expand.
.for i in outer
.  for i in inner
.    info ${i}
.  endfor
.endfor

# From https://gnats.netbsd.org/29985.
#
# Until 2008-12-21, the .for loop was expanded by replacing the variable
# value literally in the body.  This could lead to situations where the
# characters from the variable value were interpreted as markup rather than
# plain text.
#
# Until 2012-06-03, the .for loop had split the words at whitespace, without
# taking quotes into account.  This made it possible to have variable values
# like "a:\ a:\file.txt" that ended in a single backslash.  Since then, the
# variable values have been replaced with expressions of the form ${:U...},
# which are not interpreted as code anymore.
#
# As of 2020-09-22, a comment in for.c says that it may be possible to
# produce an "unwanted substitution", but there is no demonstration code yet.
#
# The above changes prevent a backslash at the end of a word from being
# interpreted as part of the code.  Because of this, the trailingBackslash
# hack in Var_Subst is no longer needed and as of 2020-09-22, has been
# removed.
.for path in a:\ a:\file.txt d:\\ d:\\file.txt
.  info ${path}
.endfor

# Ensure that braces and parentheses are properly escaped by the .for loop.
# Each line must print the same word 3 times.
# See ForLoop_SubstBody.
.for v in ( [ { ) ] } (()) [[]] {{}} )( ][ }{
.  info $v ${v} $(v)
.endfor

# As of 2020-10-25, the variable names may contain arbitrary characters,
# except for whitespace.  This allows for creative side effects. Hopefully
# nobody is misusing this "feature".
var=	outer
.for var:Q in value "quoted"
.  info ${var} ${var:Q} ${var:Q:Q}
.endfor


# XXX: A parse error or evaluation error in the items of the .for loop
# should skip the whole loop.  As of 2020-12-27, the loop is expanded twice.
.for var in word1 ${:Uword2:Z} word3
.  info XXX: Not reached ${var}
.endfor


# An empty list of variables to the left of the 'in' is a parse error.
.for in value			# expect+0: no iteration variables in for
# XXX: The loop body is evaluated once, even with the parse error above.
.  error			# expect+0: Missing argument for ".error"
.endfor				# expect+0: for-less endfor

# An empty list of iteration values to the right of the 'in' is accepted.
# Unlike in the shell, it is not a parse error.
.for var in
.  error
.endfor

# If the iteration values become empty after expanding the expressions, the
# body of the loop is not evaluated.  It is not a parse error.
.for var in ${:U}
.  error
.endfor


# The loop body can be empty.
.for var in 1 2 3
.endfor


# A mismatched .if inside a .for loop is detected each time when the loop body
# is processed.
.for var in value
.  if 0
.endfor				# expect+0: 1 open conditional

# If there are no iteration values, the loop body is not processed, and the
# check for mismatched conditionals is not performed.
.for var in ${:U}
.  if 0
.endfor


# When a .for without the corresponding .endfor occurs in an inactive branch
# of an .if, the .for directive is just skipped, it does not even need a
# corresponding .endfor.  In other words, the behavior of the parser depends
# on the actual values of the conditions in the .if clauses.
.if 0
.  for var in value		# does not need a corresponding .endfor
.endif
.endfor				# expect+0: for-less endfor
.endif				# expect+0: if-less endif


# When a .for without the corresponding .endfor occurs in an active branch of
# an .if, the parser just counts the number of .for and .endfor directives,
# without looking at any other directives.
.if 1
.  for var in value
.    endif			# expect+0: if-less endif
.  endfor			# no 'for-less endfor'
.endif				# no 'if-less endif'


# When make parses a .for loop, it assumes that there is no line break between
# the '.' and the 'for' or 'endfor', as there is no practical reason to break
# the line at this point.  When make scans the outer .for loop, it does not
# recognize the inner directives as such.  When make scans the inner .for
# loop, it recognizes the '.\n for' but does not recognize the '.\n endfor',
# as LK_FOR_BODY preserves the backslash-newline sequences.
.MAKEFLAGS: -df
.for outer in o
.\
   for inner in i
.\
   endfor
.endfor
.MAKEFLAGS: -d0


# When there is a variable definition 'scope=cmdline' from the command line
# (which has higher precedence than global variables) and a .for loop iterates
# over a variable of the same name, the expression '${scope}' expands to the
# value from the .for loop.  This is because when the body of the .for loop is
# expanded, the expression '${scope}' is textually replaced with ${:Uloop}',
# without resolving any other variable names (ForLoop_SubstBody).  Later, when
# the body of the .for loop is actually interpreted, the body text doesn't
# contain the word 'scope' anymore.
.MAKEFLAGS: scope=cmdline
.for scope in loop
.  if ${scope} != "loop"
.    error
.  endif
.endfor
