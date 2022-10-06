/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021-2022 Alfonso Sabato Siciliano
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>

#include <ctype.h>
#include <curses.h>
#include <string.h>

#include "bsddialog.h"
#include "bsddialog_theme.h"
#include "lib_util.h"

#define MINWDATE   23 /* 3 windows and their borders */
#define MINWTIME   14 /* 3 windows and their borders */

static void
drawsquare(struct bsddialog_conf *conf, WINDOW *win, const char *fmt,
    const void *value, bool focus)
{
	int h, l, w;

	getmaxyx(win, h, w);
	draw_borders(conf, win, h, w, LOWERED);
	if (focus) {
		l = 2 + w%2;
		wattron(win, t.dialog.arrowcolor);
		mvwhline(win, 0, w/2 - l/2,
		    conf->ascii_lines ? '^' : ACS_UARROW, l);
		mvwhline(win, h-1, w/2 - l/2,
		    conf->ascii_lines ? 'v' : ACS_DARROW, l);
		wattroff(win, t.dialog.arrowcolor);
	}

	if (focus)
		wattron(win, t.menu.f_namecolor);
	if (strchr(fmt, 's') != NULL)
		mvwprintw(win, 1, 1, fmt, (const char*)value);
	else
		mvwprintw(win, 1, 1, fmt, *((const int*)value));
	if (focus)
		wattroff(win, t.menu.f_namecolor);

	wrefresh(win);
}

static int
datetime_autosize(struct bsddialog_conf *conf, int rows, int cols, int *h,
    int *w, int minw, const char *text, struct buttons bs)
{
	int htext, wtext;

	if (cols == BSDDIALOG_AUTOSIZE || rows == BSDDIALOG_AUTOSIZE) {
		if (text_size(conf, rows, cols, text, &bs, 3, minw, &htext,
		    &wtext) != 0)
			return (BSDDIALOG_ERROR);
	}

	if (cols == BSDDIALOG_AUTOSIZE)
		*w = widget_min_width(conf, wtext, minw, &bs);

	if (rows == BSDDIALOG_AUTOSIZE)
		*h = widget_min_height(conf, htext, 3 /* windows */, true);

	return (0);
}

static int
datetime_checksize(int rows, int cols, int minw, struct buttons bs)
{
	int mincols;

	mincols = VBORDERS;
	mincols += buttons_min_width(bs);
	mincols = MAX(minw, mincols);

	if (cols < mincols)
		RETURN_ERROR("Few cols for this timebox/datebox");

	if (rows < 7) /* 2 button + 2 borders + 3 windows */
		RETURN_ERROR("Few rows for this timebox/datebox, at least 7");

	return (0);
}

int
bsddialog_timebox(struct bsddialog_conf *conf, const char* text, int rows,
    int cols, unsigned int *hh, unsigned int *mm, unsigned int *ss)
{
	bool loop, focusbuttons;
	int i, retval, y, x, h, w, sel;
	wint_t input;
	WINDOW *widget, *textpad, *shadow;
	struct buttons bs;
	struct myclockstruct {
		unsigned int max;
		unsigned int value;
		WINDOW *win;
	};

	if (hh == NULL || mm == NULL || ss == NULL)
		RETURN_ERROR("hh / mm / ss cannot be NULL");

	struct myclockstruct c[3] = {
		{23, *hh, NULL},
		{59, *mm, NULL},
		{59, *ss, NULL}
	};

	for (i = 0 ; i < 3; i++) {
		if (c[i].value > c[i].max)
			c[i].value = c[i].max;
	}

	get_buttons(conf, &bs, BUTTON_OK_LABEL, BUTTON_CANCEL_LABEL);

	if (set_widget_size(conf, rows, cols, &h, &w) != 0)
		return (BSDDIALOG_ERROR);
	if (datetime_autosize(conf, rows, cols, &h, &w, MINWTIME, text,
	    bs) != 0)
		return (BSDDIALOG_ERROR);
	if (datetime_checksize(h, w, MINWTIME, bs) != 0)
		return (BSDDIALOG_ERROR);
	if (set_widget_position(conf, &y, &x, h, w) != 0)
		return (BSDDIALOG_ERROR);

	if (new_dialog(conf, &shadow, &widget, y, x, h, w, &textpad, text, &bs,
	    true) != 0)
		return (BSDDIALOG_ERROR);

	pnoutrefresh(textpad, 0, 0, y+1, x+2, y+h-7, x+w-2);
	doupdate();

	c[0].win = new_boxed_window(conf, y+h-6, x + w/2 - 7, 3, 4, LOWERED);
	mvwaddch(widget, h - 5, w/2 - 3, ':');
	c[1].win = new_boxed_window(conf, y+h-6, x + w/2 - 2, 3, 4, LOWERED);
	mvwaddch(widget, h - 5, w/2 + 2, ':');
	c[2].win = new_boxed_window(conf, y+h-6, x + w/2 + 3, 3, 4, LOWERED);

	wrefresh(widget);

	sel = -1;
	loop = focusbuttons = true;
	while (loop) {
		for (i = 0; i < 3; i++)
			drawsquare(conf, c[i].win, "%02d", &c[i].value,
			    sel == i);

		if (get_wch(&input) == ERR)
			continue;
		switch(input) {
		case KEY_ENTER:
		case 10: /* Enter */
			if (focusbuttons || conf->button.always_active) {
				retval = bs.value[bs.curr];
				loop = false;
			}
			break;
		case 27: /* Esc */
			if (conf->key.enable_esc) {
				retval = BSDDIALOG_ESC;
				loop = false;
			}
			break;
		case KEY_RIGHT:
		case '\t': /* TAB */
			if (focusbuttons) {
				bs.curr++;
				focusbuttons = bs.curr < (int)bs.nbuttons ?
				    true : false;
				if (focusbuttons == false) {
					sel = 0;
					bs.curr = conf->button.always_active ? 0 : -1;
				}
			} else {
				sel++;
				focusbuttons = sel > 2 ? true : false;
				if (focusbuttons) {
					bs.curr = 0;
				}
			}
			draw_buttons(widget, bs, true);
			wrefresh(widget);
			break;
		case KEY_LEFT:
			if (focusbuttons) {
				bs.curr--;
				focusbuttons = bs.curr < 0 ? false : true;
				if (focusbuttons == false) {
					sel = 2;
					bs.curr = conf->button.always_active ? 0 : -1;
				}
			} else {
				sel--;
				focusbuttons = sel < 0 ? true : false;
				if (focusbuttons)
					bs.curr = (int)bs.nbuttons - 1;
			}
			draw_buttons(widget, bs, true);
			wrefresh(widget);
			break;
		case KEY_UP:
			if (focusbuttons) {
				sel = 0;
				focusbuttons = false;
				bs.curr = conf->button.always_active ? 0 : -1;
				draw_buttons(widget, bs, true);
				wrefresh(widget);
			} else { c[sel].value = c[sel].value > 0 ?
			    c[sel].value - 1 : c[sel].max;
			}
			break;
		case KEY_DOWN:
			if (focusbuttons)
				break;
			c[sel].value = c[sel].value < c[sel].max ?
			    c[sel].value + 1 : 0;
			break;
		case KEY_F(1):
			if (conf->key.f1_file == NULL &&
			    conf->key.f1_message == NULL)
				break;
			if (f1help(conf) != 0)
				return (BSDDIALOG_ERROR);
			/* No break, screen size can change */
		case KEY_RESIZE:
			/* Important for decreasing screen */
			hide_widget(y, x, h, w, conf->shadow);
			refresh();

			if (set_widget_size(conf, rows, cols, &h, &w) != 0)
				return (BSDDIALOG_ERROR);
			if (datetime_autosize(conf, rows, cols, &h, &w,
			    MINWTIME, text, bs) != 0)
				return (BSDDIALOG_ERROR);
			if (datetime_checksize(h, w, MINWTIME, bs) != 0)
				return (BSDDIALOG_ERROR);
			if (set_widget_position(conf, &y, &x, h, w) != 0)
				return (BSDDIALOG_ERROR);

			if (update_dialog(conf, shadow, widget, y, x, h, w,
			    textpad, text, &bs, true) != 0)
				return (BSDDIALOG_ERROR);

			doupdate();

			mvwaddch(widget, h - 5, w/2 - 3, ':');
			mvwaddch(widget, h - 5, w/2 + 2, ':');
			wrefresh(widget);

			prefresh(textpad, 0, 0, y+1, x+2, y+h-7, x+w-2);

			wclear(c[0].win);
			mvwin(c[0].win, y + h - 6, x + w/2 - 7);
			wclear(c[1].win);
			mvwin(c[1].win, y + h - 6, x + w/2 - 2);
			wclear(c[2].win);
			mvwin(c[2].win, y + h - 6, x + w/2 + 3);

			/* Important to avoid grey lines expanding screen */
			refresh();
			break;
		default:
			if (shortcut_buttons(input, &bs)) {
				retval = bs.value[bs.curr];
				loop = false;
			}
		}
	}

	if (retval == BSDDIALOG_OK) {
		*hh = c[0].value;
		*mm = c[1].value;
		*ss = c[2].value;
	}

	for (i = 0; i < 3; i++)
		delwin(c[i].win);
	end_dialog(conf, shadow, widget, textpad);

	return (retval);
}

int
bsddialog_datebox(struct bsddialog_conf *conf, const char *text, int rows,
    int cols, unsigned int *yy, unsigned int *mm, unsigned int *dd)
{
	bool loop, focusbuttons;
	int i, retval, y, x, h, w, sel;
	wint_t input;
	WINDOW *widget, *textpad, *shadow;
	struct buttons bs;
	struct calendar {
		int max;
		int value;
		WINDOW *win;
		unsigned int x;
	};
	struct month {
		const char *name;
		unsigned int days;
	};

	if (yy == NULL || mm == NULL || dd == NULL)
		RETURN_ERROR("yy / mm / dd cannot be NULL");

	struct calendar c[3] = {
		{9999, *yy, NULL, 4 },
		{12,   *mm, NULL, 9 },
		{31,   *dd, NULL, 2 }
	};

	struct month m[12] = {
		{ "January", 31 }, { "February", 28 }, { "March",     31 },
		{ "April",   30 }, { "May",      31 }, { "June",      30 },
		{ "July",    31 }, { "August",   31 }, { "September", 30 },
		{ "October", 31 }, { "November", 30 }, { "December",  31 }
	};

	for (i = 0 ; i < 3; i++) {
		if (c[i].value > c[i].max)
			c[i].value = c[i].max;
		if (c[i].value < 1)
			c[i].value = 1;
	}
	c[2].max = m[c[1].value -1].days;
	if (c[1].value == 2 && ISLEAP(c[0].value))
		c[2].max = 29;
	if (c[2].value > c[2].max)
		c[2].value = c[2].max;

	get_buttons(conf, &bs, BUTTON_OK_LABEL, BUTTON_CANCEL_LABEL);

	if (set_widget_size(conf, rows, cols, &h, &w) != 0)
		return (BSDDIALOG_ERROR);
	if (datetime_autosize(conf, rows, cols, &h, &w, MINWDATE, text,
	    bs) != 0)
		return (BSDDIALOG_ERROR);
	if (datetime_checksize(h, w, MINWDATE, bs) != 0)
		return (BSDDIALOG_ERROR);
	if (set_widget_position(conf, &y, &x, h, w) != 0)
		return (BSDDIALOG_ERROR);

	if (new_dialog(conf, &shadow, &widget, y, x, h, w, &textpad, text, &bs,
	    true) != 0)
		return (BSDDIALOG_ERROR);

	pnoutrefresh(textpad, 0, 0, y+1, x+2, y+h-7, x+w-2);
	doupdate();

	c[0].win = new_boxed_window(conf, y+h-6, x + w/2 - 11, 3, 6, LOWERED);
	mvwaddch(widget, h - 5, w/2 - 5, '/');
	c[1].win = new_boxed_window(conf, y+h-6, x + w/2 - 4, 3, 11, LOWERED);
	mvwaddch(widget, h - 5, w/2 + 7, '/');
	c[2].win = new_boxed_window(conf, y+h-6, x + w/2 + 8, 3, 4, LOWERED);

	wrefresh(widget);

	sel = -1;
	loop = focusbuttons = true;
	while (loop) {
		drawsquare(conf, c[0].win, "%4d", &c[0].value, sel == 0);
		drawsquare(conf, c[1].win, "%9s", m[c[1].value-1].name,
		    sel == 1);
		drawsquare(conf, c[2].win, "%02d", &c[2].value, sel == 2);

		if (get_wch(&input) == ERR)
			continue;
		switch(input) {
		case KEY_ENTER:
		case 10: /* Enter */
			if (focusbuttons || conf->button.always_active) {
				retval = bs.value[bs.curr];
				loop = false;
			}
			break;
		case 27: /* Esc */
			if (conf->key.enable_esc) {
				retval = BSDDIALOG_ESC;
				loop = false;
			}
			break;
		case KEY_RIGHT:
		case '\t': /* TAB */
			if (focusbuttons) {
				bs.curr++;
				focusbuttons = bs.curr < (int)bs.nbuttons ?
				    true : false;
				if (focusbuttons == false) {
					sel = 0;
					bs.curr = conf->button.always_active ? 0 : -1;
				}
			} else {
				sel++;
				focusbuttons = sel > 2 ? true : false;
				if (focusbuttons) {
					bs.curr = 0;
				}
			}
			draw_buttons(widget, bs, true);
			wrefresh(widget);
			break;
		case KEY_LEFT:
			if (focusbuttons) {
				bs.curr--;
				focusbuttons = bs.curr < 0 ? false : true;
				if (focusbuttons == false) {
					sel = 2;
					bs.curr = conf->button.always_active ? 0 : -1;
				}
			} else {
				sel--;
				focusbuttons = sel < 0 ? true : false;
				if (focusbuttons)
					bs.curr = (int)bs.nbuttons - 1;
			}
			draw_buttons(widget, bs, true);
			wrefresh(widget);
			break;
		case KEY_UP:
			if (focusbuttons) {
				sel = 0;
				focusbuttons = false;
				bs.curr = conf->button.always_active ? 0 : -1;
				draw_buttons(widget, bs, true);
				wrefresh(widget);
			} else {
				c[sel].value = c[sel].value > 1 ?
				    c[sel].value - 1 : c[sel].max ;
				/* if mount change */
				c[2].max = m[c[1].value -1].days;
				/* if year change */
				if (c[1].value == 2 && ISLEAP(c[0].value))
					c[2].max = 29;
				/* set new day */
				if (c[2].value > c[2].max)
					c[2].value = c[2].max;
			}
			break;
		case KEY_DOWN:
			if (focusbuttons)
				break;
			c[sel].value = c[sel].value < c[sel].max ?
			    c[sel].value + 1 : 1;
			/* if mount change */
			c[2].max = m[c[1].value -1].days;
			/* if year change */
			if (c[1].value == 2 && ISLEAP(c[0].value))
				c[2].max = 29;
			/* set new day */
			if (c[2].value > c[2].max)
				c[2].value = c[2].max;
			break;
		case KEY_F(1):
			if (conf->key.f1_file == NULL &&
			    conf->key.f1_message == NULL)
				break;
			if (f1help(conf) != 0)
				return (BSDDIALOG_ERROR);
			/* No break, screen size can change */
		case KEY_RESIZE:
			/* Important for decreasing screen */
			hide_widget(y, x, h, w, conf->shadow);
			refresh();

			if (set_widget_size(conf, rows, cols, &h, &w) != 0)
				return (BSDDIALOG_ERROR);
			if (datetime_autosize(conf, rows, cols, &h, &w,
			    MINWDATE, text, bs) != 0)
				return (BSDDIALOG_ERROR);
			if (datetime_checksize(h, w, MINWDATE, bs) != 0)
				return (BSDDIALOG_ERROR);
			if (set_widget_position(conf, &y, &x, h, w) != 0)
				return (BSDDIALOG_ERROR);

			if (update_dialog(conf, shadow, widget, y, x, h, w,
			    textpad, text, &bs, true) != 0)
				return (BSDDIALOG_ERROR);
			doupdate();

			mvwaddch(widget, h - 5, w/2 - 5, '/');
			mvwaddch(widget, h - 5, w/2 + 7, '/');
			wrefresh(widget);

			prefresh(textpad, 0, 0, y+1, x+2, y+h-7, x+w-2);

			wclear(c[0].win);
			mvwin(c[0].win, y + h - 6, x + w/2 - 11);
			wclear(c[1].win);
			mvwin(c[1].win, y + h - 6, x + w/2 - 4);
			wclear(c[2].win);
			mvwin(c[2].win, y + h - 6, x + w/2 + 8);

			/* Important to avoid grey lines expanding screen */
			refresh();
			break;
		default:
			if (shortcut_buttons(input, &bs)) {
				retval = bs.value[bs.curr];
				loop = false;
			}
		}
	}

	if (retval == BSDDIALOG_OK) {
		*yy = c[0].value;
		*mm = c[1].value;
		*dd = c[2].value;
	}

	for (i = 0; i < 3; i++)
		delwin(c[i].win);
	end_dialog(conf, shadow, widget, textpad);

	return (retval);
}