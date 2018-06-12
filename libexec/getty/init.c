/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
#if 0
static char sccsid[] = "@(#)from: init.c	8.1 (Berkeley) 6/4/93";
#endif
static const char rcsid[] =
  "$FreeBSD$";
#endif /* not lint */

/*
 * Getty table initializations.
 *
 * Melbourne getty.
 */
#include <termios.h>
#include "gettytab.h"
#include "extern.h"
#include "pathnames.h"

static char loginmsg[] = "login: ";
static char nullstr[] = "";
static char loginprg[] = _PATH_LOGIN;
static char datefmt[] = "%+";

struct	gettystrs gettystrs[] = {
	{ "nx" },			/* next table */
	{ "cl" },			/* screen clear characters */
	{ "im" },			/* initial message */
	{ "lm", loginmsg },		/* login message */
	{ "er", &omode.c_cc[VERASE] },	/* erase character */
	{ "kl", &omode.c_cc[VKILL] },	/* kill character */
	{ "et", &omode.c_cc[VEOF] },	/* eof chatacter (eot) */
	{ "pc", nullstr },		/* pad character */
	{ "tt" },			/* terminal type */
	{ "ev" },			/* environment */
	{ "lo", loginprg },		/* login program */
	{ "hn", hostname },		/* host name */
	{ "he" },			/* host name edit */
	{ "in", &omode.c_cc[VINTR] },	/* interrupt char */
	{ "qu", &omode.c_cc[VQUIT] },	/* quit char */
	{ "xn", &omode.c_cc[VSTART] },	/* XON (start) char */
	{ "xf", &omode.c_cc[VSTOP] },	/* XOFF (stop) char */
	{ "bk", &omode.c_cc[VEOL] },	/* brk char (alt \n) */
	{ "su", &omode.c_cc[VSUSP] },	/* suspend char */
	{ "ds", &omode.c_cc[VDSUSP] },	/* delayed suspend */
	{ "rp", &omode.c_cc[VREPRINT] },/* reprint char */
	{ "fl", &omode.c_cc[VDISCARD] },/* flush output */
	{ "we", &omode.c_cc[VWERASE] },	/* word erase */
	{ "ln", &omode.c_cc[VLNEXT] },	/* literal next */
	{ "Lo" },			/* locale for strftime() */
	{ "pp" },			/* ppp login program */
	{ "if" },			/* sysv-like 'issue' filename */
	{ "ic" },			/* modem init-chat */
	{ "ac" },			/* modem answer-chat */
	{ "al" },			/* user to auto-login */
	{ "df", datefmt},		/* format for strftime() */
	{ "iM" },			/* initial message program */
	{ 0 }
};

struct	gettynums gettynums[] = {
	{ "is" },			/* input speed */
	{ "os" },			/* output speed */
	{ "sp" },			/* both speeds */
	{ "nd" },			/* newline delay */
	{ "cd" },			/* carriage-return delay */
	{ "td" },			/* tab delay */
	{ "fd" },			/* form-feed delay */
	{ "bd" },			/* backspace delay */
	{ "to" },			/* timeout */
	{ "f0" },			/* output flags */
	{ "f1" },			/* input flags */
	{ "f2" },			/* user mode flags */
	{ "pf" },			/* delay before flush at 1st prompt */
	{ "c0" },			/* output c_flags */
	{ "c1" },			/* input c_flags */
	{ "c2" },			/* user mode c_flags */
	{ "i0" },			/* output i_flags */
	{ "i1" },			/* input i_flags */
	{ "i2" },			/* user mode i_flags */
	{ "l0" },			/* output l_flags */
	{ "l1" },			/* input l_flags */
	{ "l2" },			/* user mode l_flags */
	{ "o0" },			/* output o_flags */
	{ "o1" },			/* input o_flags */
	{ "o2" },			/* user mode o_flags */
 	{ "de" },   	    	    	/* delay before sending 1st prompt */
	{ "rt" },			/* reset timeout */
	{ "ct" },			/* chat script timeout */
	{ "dc" },			/* debug chat script value */
  	{ 0 }
};
  

struct	gettyflags gettyflags[] = {
	{ "ht",	0 },			/* has tabs */
	{ "nl",	1 },			/* has newline char */
	{ "ep",	0 },			/* even parity */
	{ "op",	0 },			/* odd parity */
	{ "ap",	0 },			/* any parity */
	{ "ec",	1 },			/* no echo */
	{ "co",	0 },			/* console special */
	{ "cb",	0 },			/* crt backspace */
	{ "ck",	0 },			/* crt kill */
	{ "ce",	0 },			/* crt erase */
	{ "pe",	0 },			/* printer erase */
	{ "rw",	1 },			/* don't use raw */
	{ "xc",	1 },			/* don't ^X ctl chars */
	{ "lc",	0 },			/* terminal las lower case */
	{ "uc",	0 },			/* terminal has no lower case */
	{ "ig",	0 },			/* ignore garbage */
	{ "ps",	0 },			/* do port selector speed select */
	{ "hc",	1 },			/* don't set hangup on close */
	{ "ub", 0 },			/* unbuffered output */
	{ "ab", 0 },			/* auto-baud detect with '\r' */
	{ "dx", 0 },			/* set decctlq */
	{ "np", 0 },			/* no parity at all (8bit chars) */
	{ "mb", 0 },			/* do MDMBUF flow control */
	{ "hw", 0 },			/* do CTSRTS flow control */
	{ "nc", 0 },			/* set clocal (no carrier) */
	{ "pl", 0 },			/* use PPP instead of login(1) */
	{ 0 }
};
