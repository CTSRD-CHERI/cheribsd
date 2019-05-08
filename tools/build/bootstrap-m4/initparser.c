/* original parser id follows */
/* yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93" */
/* (use YYMAJOR/YYMINOR for ifdefs dependent on parser version) */

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20170430

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)
#define YYENOMEM       (-2)
#define YYEOF          0
#define YYPREFIX "yy"

#define YYPURE 0

#line 2 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
/* $OpenBSD: parser.y,v 1.7 2012/04/12 17:00:11 espie Exp $ */
/*
 * Copyright (c) 2004 Marc Espie <espie@cvs.openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $FreeBSD$
 */

#include <math.h>
#include <stdint.h>
#define YYSTYPE	int32_t
extern int32_t end_result;
extern int yylex(void);
extern int yyerror(const char *);
#line 47 "parser.c"

#if ! defined(YYSTYPE) && ! defined(YYSTYPE_IS_DECLARED)
/* Default: YYSTYPE is the semantic value type. */
typedef int YYSTYPE;
# define YYSTYPE_IS_DECLARED 1
#endif

/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

/* Parameters sent to yyerror. */
#ifndef YYERROR_DECL
#define YYERROR_DECL() yyerror(const char *s)
#endif
#ifndef YYERROR_CALL
#define YYERROR_CALL(msg) yyerror(msg)
#endif

extern int YYPARSE_DECL();

#define NUMBER 257
#define ERROR 258
#define LOR 259
#define LAND 260
#define EQ 261
#define NE 262
#define LE 263
#define GE 264
#define LSHIFT 265
#define RSHIFT 266
#define EXPONENT 267
#define UMINUS 268
#define UPLUS 269
#define YYERRCODE 256
typedef int YYINT;
static const YYINT yylhs[] = {                           -1,
    0,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,
};
static const YYINT yylen[] = {                            2,
    1,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    2,    2,    2,    2,    1,
};
static const YYINT yydefred[] = {                         0,
   26,    0,    0,    0,    0,    0,    0,    0,   23,   22,
   24,   25,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   21,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,
};
static const YYINT yydgoto[] = {                          7,
    8,
};
static const YYINT yysindex[] = {                        95,
    0,   95,   95,   95,   95,   95,    0,  397,    0,    0,
    0,    0,  383,   95,   95,   95,   95,   95,   95,   95,
   95,   95,   95,   95,   95,   95,   95,   95,   95,   95,
   95,   95,    0,  428,  471,  482,  185,  437,  493,  493,
  -10,  -10,  -10,  -10,  -23,  -23,  -34,  -34, -267, -267,
 -267, -267,
};
static const YYINT yyrindex[] = {                         0,
    0,    0,    0,    0,    0,    0,    0,    2,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   11,   62,   23,  101,  308,  201,  243,
  124,  130,  144,  155,   79,  116,   51,   67,    1,   12,
   28,   40,
};
static const YYINT yygindex[] = {                         0,
  582,
};
#define YYTABLESIZE 760
static const YYINT yytable[] = {                         32,
    5,    1,   31,    0,    0,    0,    0,   29,    0,    0,
   20,    6,   30,   31,    0,    0,    0,    0,   29,   27,
    0,   28,   18,   30,    0,    0,   31,    7,    0,    0,
    0,   29,   27,    0,   28,    0,   30,    5,    5,    4,
    0,    5,    5,    5,    0,    5,    0,    5,    6,    6,
    2,   20,    6,    6,    6,    0,    6,    0,    6,    0,
    5,   19,    5,   18,    7,    7,    3,    0,    7,    7,
    7,    6,    7,    6,    7,    0,    4,    4,    8,    0,
    4,    4,    4,    0,    4,    0,    4,    7,    2,    7,
    0,    2,    0,    2,    5,    2,    0,    0,    0,    4,
   17,    4,   19,    0,    3,    6,    0,    3,    0,    3,
    2,    3,    2,    0,    0,    9,    8,    0,    0,    8,
    0,    7,    0,   10,    5,    0,    3,    4,    3,   12,
    0,    0,    0,    4,    6,    6,    0,    2,    8,    3,
    8,   17,    0,   11,    2,    0,   18,    0,    0,    0,
    0,    7,    0,    9,   13,    0,    9,    0,    0,    0,
    3,   10,    0,    4,   10,    0,    0,   12,    0,    0,
   12,    0,    8,    0,    2,    9,    0,    9,    0,    0,
    0,   11,    0,   10,   11,   10,    0,    0,    0,   12,
    3,   12,   13,    0,   17,   13,    0,    0,    0,    0,
   14,    0,    8,   11,    0,   11,    0,    0,    0,    9,
    0,    0,    0,    0,   13,    0,   13,   10,    0,    0,
    5,   31,   18,   12,   17,    0,   29,   27,    0,   28,
    0,   30,   32,    0,    0,    0,    0,   11,   14,    9,
    0,   14,   15,   32,   21,    0,   23,   10,   13,    0,
    0,    0,    0,   12,   25,   26,   32,    0,    0,    5,
    5,    5,    5,    5,    5,    5,    5,   11,    0,   20,
    6,    6,    6,    6,    6,    6,    6,    6,   13,    0,
   15,   18,   18,   15,    0,    0,    7,    7,    7,    7,
    7,    7,    7,    7,   14,    0,    0,    0,    4,    4,
    4,    4,    4,    4,    4,    4,    0,   16,    0,    2,
    2,    2,    2,    2,    2,    2,    2,    0,    0,    0,
   19,   19,    0,    0,   14,    3,    3,    3,    3,    3,
    3,    3,    3,    0,    0,    0,   15,    8,    8,    8,
    8,    8,    8,    8,    8,   16,    0,    0,   16,    0,
    0,    1,    0,    0,    0,    0,    0,    0,    0,   17,
   17,    0,    0,    0,    0,    0,   15,    0,    0,    0,
    0,    0,    0,    0,    9,    9,    9,    9,    9,    9,
    9,    9,   10,   10,   10,   10,   10,   10,   12,   12,
   12,   12,   12,   12,    0,    0,    0,    0,    0,    0,
    0,   16,   11,   11,   11,   11,   11,   11,    0,    0,
    0,    0,    0,   13,   13,   13,   13,   13,   13,   31,
   18,    0,    0,   33,   29,   27,    0,   28,    0,   30,
    0,   16,    0,   31,   18,    0,    0,    0,   29,   27,
    0,   28,   21,   30,   23,   19,   20,   22,   24,   25,
   26,   32,    0,    0,    0,    0,   21,    0,   23,   14,
   14,   14,   14,    0,   31,   18,    0,    0,    0,   29,
   27,    0,   28,   31,   30,    0,   17,    0,   29,   27,
    0,   28,    0,   30,    0,    0,    0,   21,    0,   23,
   17,    0,    0,    0,    0,    0,   21,    0,   23,    0,
    0,   15,   15,   15,   15,    0,   16,   31,   18,    0,
    0,    0,   29,   27,    0,   28,    0,   30,   31,   18,
   16,   17,    0,   29,   27,    0,   28,    0,   30,   31,
   21,    0,   23,    0,   29,   27,    0,   28,    0,   30,
    0,   21,    0,   23,    0,    0,    0,    0,    0,    0,
    0,   16,   21,    0,   23,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   17,    0,   16,   16,    0,    0,
    0,    0,    0,    0,    0,   17,    0,    0,    0,    0,
    0,    0,    0,    9,   10,   11,   12,   13,    0,    0,
    0,    0,    0,    0,   16,   34,   35,   36,   37,   38,
   39,   40,   41,   42,   43,   44,   45,   46,   47,   48,
   49,   50,   51,   52,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   14,   15,   19,   20,   22,   24,   25,   26,   32,
    0,    0,    0,    0,    0,   14,   15,   19,   20,   22,
   24,   25,   26,   32,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   15,   19,   20,
   22,   24,   25,   26,   32,    0,    0,   19,   20,   22,
   24,   25,   26,   32,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   19,   20,   22,   24,   25,   26,   32,    0,    0,
    0,    0,   19,   20,   22,   24,   25,   26,   32,    0,
    0,    0,    0,    0,    0,   22,   24,   25,   26,   32,
};
static const YYINT yycheck[] = {                        267,
    0,    0,   37,   -1,   -1,   -1,   -1,   42,   -1,   -1,
    0,    0,   47,   37,   -1,   -1,   -1,   -1,   42,   43,
   -1,   45,    0,   47,   -1,   -1,   37,    0,   -1,   -1,
   -1,   42,   43,   -1,   45,   -1,   47,   37,   38,    0,
   -1,   41,   42,   43,   -1,   45,   -1,   47,   37,   38,
    0,   41,   41,   42,   43,   -1,   45,   -1,   47,   -1,
   60,    0,   62,   41,   37,   38,    0,   -1,   41,   42,
   43,   60,   45,   62,   47,   -1,   37,   38,    0,   -1,
   41,   42,   43,   -1,   45,   -1,   47,   60,   38,   62,
   -1,   41,   -1,   43,   94,   45,   -1,   -1,   -1,   60,
    0,   62,   41,   -1,   38,   94,   -1,   41,   -1,   43,
   60,   45,   62,   -1,   -1,    0,   38,   -1,   -1,   41,
   -1,   94,   -1,    0,  124,   -1,   60,   33,   62,    0,
   -1,   -1,   -1,   94,   40,  124,   -1,   43,   60,   45,
   62,   41,   -1,    0,   94,   -1,  124,   -1,   -1,   -1,
   -1,  124,   -1,   38,    0,   -1,   41,   -1,   -1,   -1,
   94,   38,   -1,  124,   41,   -1,   -1,   38,   -1,   -1,
   41,   -1,   94,   -1,  124,   60,   -1,   62,   -1,   -1,
   -1,   38,   -1,   60,   41,   62,   -1,   -1,   -1,   60,
  124,   62,   38,   -1,   94,   41,   -1,   -1,   -1,   -1,
    0,   -1,  124,   60,   -1,   62,   -1,   -1,   -1,   94,
   -1,   -1,   -1,   -1,   60,   -1,   62,   94,   -1,   -1,
  126,   37,   38,   94,  124,   -1,   42,   43,   -1,   45,
   -1,   47,  267,   -1,   -1,   -1,   -1,   94,   38,  124,
   -1,   41,    0,  267,   60,   -1,   62,  124,   94,   -1,
   -1,   -1,   -1,  124,  265,  266,  267,   -1,   -1,  259,
  260,  261,  262,  263,  264,  265,  266,  124,   -1,  259,
  259,  260,  261,  262,  263,  264,  265,  266,  124,   -1,
   38,  259,  260,   41,   -1,   -1,  259,  260,  261,  262,
  263,  264,  265,  266,   94,   -1,   -1,   -1,  259,  260,
  261,  262,  263,  264,  265,  266,   -1,    0,   -1,  259,
  260,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  259,  260,   -1,   -1,  124,  259,  260,  261,  262,  263,
  264,  265,  266,   -1,   -1,   -1,   94,  259,  260,  261,
  262,  263,  264,  265,  266,   38,   -1,   -1,   41,   -1,
   -1,  257,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  259,
  260,   -1,   -1,   -1,   -1,   -1,  124,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  259,  260,  261,  262,  263,  264,
  265,  266,  259,  260,  261,  262,  263,  264,  259,  260,
  261,  262,  263,  264,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   94,  259,  260,  261,  262,  263,  264,   -1,   -1,
   -1,   -1,   -1,  259,  260,  261,  262,  263,  264,   37,
   38,   -1,   -1,   41,   42,   43,   -1,   45,   -1,   47,
   -1,  124,   -1,   37,   38,   -1,   -1,   -1,   42,   43,
   -1,   45,   60,   47,   62,  261,  262,  263,  264,  265,
  266,  267,   -1,   -1,   -1,   -1,   60,   -1,   62,  259,
  260,  261,  262,   -1,   37,   38,   -1,   -1,   -1,   42,
   43,   -1,   45,   37,   47,   -1,   94,   -1,   42,   43,
   -1,   45,   -1,   47,   -1,   -1,   -1,   60,   -1,   62,
   94,   -1,   -1,   -1,   -1,   -1,   60,   -1,   62,   -1,
   -1,  259,  260,  261,  262,   -1,  124,   37,   38,   -1,
   -1,   -1,   42,   43,   -1,   45,   -1,   47,   37,   38,
  124,   94,   -1,   42,   43,   -1,   45,   -1,   47,   37,
   60,   -1,   62,   -1,   42,   43,   -1,   45,   -1,   47,
   -1,   60,   -1,   62,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  124,   60,   -1,   62,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   94,   -1,  259,  260,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   94,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,    2,    3,    4,    5,    6,   -1,   -1,
   -1,   -1,   -1,   -1,  124,   14,   15,   16,   17,   18,
   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,
   29,   30,   31,   32,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  259,  260,  261,  262,  263,  264,  265,  266,  267,
   -1,   -1,   -1,   -1,   -1,  259,  260,  261,  262,  263,
  264,  265,  266,  267,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  260,  261,  262,
  263,  264,  265,  266,  267,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  261,  262,  263,  264,  265,  266,  267,   -1,   -1,
   -1,   -1,  261,  262,  263,  264,  265,  266,  267,   -1,
   -1,   -1,   -1,   -1,   -1,  263,  264,  265,  266,  267,
};
#define YYFINAL 7
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 269
#define YYUNDFTOKEN 273
#define YYTRANSLATE(a) ((a) > YYMAXTOKEN ? YYUNDFTOKEN : (a))
#if YYDEBUG
static const char *const yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,"'%'","'&'",0,"'('","')'","'*'","'+'",0,"'-'",0,"'/'",0,0,0,0,0,0,0,
0,0,0,0,0,"'<'",0,"'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,"'^'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'|'",0,
"'~'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,"NUMBER","ERROR","LOR","LAND","EQ","NE","LE","GE",
"LSHIFT","RSHIFT","EXPONENT","UMINUS","UPLUS",0,0,0,"illegal-symbol",
};
static const char *const yyrule[] = {
"$accept : top",
"top : expr",
"expr : expr '+' expr",
"expr : expr '-' expr",
"expr : expr EXPONENT expr",
"expr : expr '*' expr",
"expr : expr '/' expr",
"expr : expr '%' expr",
"expr : expr LSHIFT expr",
"expr : expr RSHIFT expr",
"expr : expr '<' expr",
"expr : expr '>' expr",
"expr : expr LE expr",
"expr : expr GE expr",
"expr : expr EQ expr",
"expr : expr NE expr",
"expr : expr '&' expr",
"expr : expr '^' expr",
"expr : expr '|' expr",
"expr : expr LAND expr",
"expr : expr LOR expr",
"expr : '(' expr ')'",
"expr : '-' expr",
"expr : '+' expr",
"expr : '!' expr",
"expr : '~' expr",
"expr : NUMBER",

};
#endif

int      yydebug;
int      yynerrs;

int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH  10000
#endif
#endif

#define YYINITSTACKSIZE 200

typedef struct {
    unsigned stacksize;
    YYINT    *s_base;
    YYINT    *s_mark;
    YYINT    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
/* variables for the parser stack */
static YYSTACKDATA yystack;
#line 86 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"

#line 385 "parser.c"

#if YYDEBUG
#include <stdio.h>	/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    YYINT *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return YYENOMEM;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = (int) (data->s_mark - data->s_base);
    newss = (YYINT *)realloc(data->s_base, newsize * sizeof(*newss));
    if (newss == 0)
        return YYENOMEM;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs));
    if (newvs == 0)
        return YYENOMEM;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yym = 0;
    yyn = 0;
    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        yychar = YYLEX;
        if (yychar < 0) yychar = YYEOF;
#if YYDEBUG
        if (yydebug)
        {
            if ((yys = yyname[YYTRANSLATE(yychar)]) == NULL) yys = yyname[YYUNDFTOKEN];
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if (((yyn = yysindex[yystate]) != 0) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == (YYINT) yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if (((yyn = yyrindex[yystate]) != 0) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == (YYINT) yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag != 0) goto yyinrecovery;

    YYERROR_CALL("syntax error");

    goto yyerrlab; /* redundant goto avoids 'unused label' warning */
yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if (((yyn = yysindex[*yystack.s_mark]) != 0) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == (YYINT) YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == YYEOF) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            if ((yys = yyname[YYTRANSLATE(yychar)]) == NULL) yys = yyname[YYUNDFTOKEN];
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym > 0)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);

    switch (yyn)
    {
case 1:
#line 45 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ end_result = yystack.l_mark[0]; }
break;
case 2:
#line 47 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] + yystack.l_mark[0]; }
break;
case 3:
#line 48 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] - yystack.l_mark[0]; }
break;
case 4:
#line 49 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = pow(yystack.l_mark[-2], yystack.l_mark[0]); }
break;
case 5:
#line 50 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] * yystack.l_mark[0]; }
break;
case 6:
#line 51 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{
		if (yystack.l_mark[0] == 0) {
			yyerror("division by zero");
			exit(1);
		}
		yyval = yystack.l_mark[-2] / yystack.l_mark[0];
	}
break;
case 7:
#line 58 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ 
		if (yystack.l_mark[0] == 0) {
			yyerror("modulo zero");
			exit(1);
		}
		yyval = yystack.l_mark[-2] % yystack.l_mark[0];
	}
break;
case 8:
#line 65 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] << yystack.l_mark[0]; }
break;
case 9:
#line 66 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] >> yystack.l_mark[0]; }
break;
case 10:
#line 67 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] < yystack.l_mark[0]; }
break;
case 11:
#line 68 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] > yystack.l_mark[0]; }
break;
case 12:
#line 69 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] <= yystack.l_mark[0]; }
break;
case 13:
#line 70 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] >= yystack.l_mark[0]; }
break;
case 14:
#line 71 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] == yystack.l_mark[0]; }
break;
case 15:
#line 72 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] != yystack.l_mark[0]; }
break;
case 16:
#line 73 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] & yystack.l_mark[0]; }
break;
case 17:
#line 74 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] ^ yystack.l_mark[0]; }
break;
case 18:
#line 75 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] | yystack.l_mark[0]; }
break;
case 19:
#line 76 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] && yystack.l_mark[0]; }
break;
case 20:
#line 77 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-2] || yystack.l_mark[0]; }
break;
case 21:
#line 78 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[-1]; }
break;
case 22:
#line 79 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = -yystack.l_mark[0]; }
break;
case 23:
#line 80 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = yystack.l_mark[0]; }
break;
case 24:
#line 81 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = !yystack.l_mark[0]; }
break;
case 25:
#line 82 "/home/alr48/devel/freebsd/usr.bin/m4/parser.y"
	{ yyval = ~yystack.l_mark[0]; }
break;
#line 696 "parser.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            yychar = YYLEX;
            if (yychar < 0) yychar = YYEOF;
#if YYDEBUG
            if (yydebug)
            {
                if ((yys = yyname[YYTRANSLATE(yychar)]) == NULL) yys = yyname[YYUNDFTOKEN];
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == YYEOF) goto yyaccept;
        goto yyloop;
    }
    if (((yyn = yygindex[yym]) != 0) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == (YYINT) yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack) == YYENOMEM) goto yyoverflow;
    *++yystack.s_mark = (YYINT) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    YYERROR_CALL("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
