/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012 NetApp, Inc.
 * Copyright (c) 2013 Neel Natu <neel@freebsd.org>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#include <capsicum_helpers.h>
#endif

#include <machine/vmm_snapshot.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sysexits.h>

#include "mevent.h"
#include "uart_emul.h"
#include "debug.h"

#define	FIFOSZ	16

static bool uart_stdio;		/* stdio in use for i/o */
static struct termios tio_stdio_orig;

struct fifo {
	uint8_t	buf[FIFOSZ];
	int	rindex;		/* index to read from */
	int	windex;		/* index to write to */
	int	num;		/* number of characters in the fifo */
	int	size;		/* size of the fifo */
};

struct ttyfd {
	bool	opened;
	int	rfd;		/* fd for reading */
	int	wfd;		/* fd for writing, may be == rfd */
};

struct uart_backend {
	struct fifo rxfifo;
	struct mevent *mev;
	struct ttyfd tty;
};

static void
ttyclose(void)
{

	tcsetattr(STDIN_FILENO, TCSANOW, &tio_stdio_orig);
}

static void
ttyopen(struct ttyfd *tf)
{
	struct termios orig, new;

	tcgetattr(tf->rfd, &orig);
	new = orig;
	cfmakeraw(&new);
	new.c_cflag |= CLOCAL;
	tcsetattr(tf->rfd, TCSANOW, &new);
	if (uart_stdio) {
		tio_stdio_orig = orig;
		atexit(ttyclose);
	}
	raw_stdio = 1;
}

static int
ttyread(struct ttyfd *tf)
{
	unsigned char rb;

	if (read(tf->rfd, &rb, 1) == 1)
		return (rb);
	else
		return (-1);
}

static void
ttywrite(struct ttyfd *tf, unsigned char wb)
{

	(void)write(tf->wfd, &wb, 1);
}

void
uart_rxfifo_reset(struct uart_backend *sc, int size)
{
	char flushbuf[32];
	struct fifo *fifo;
	ssize_t nread;
	int error;

	fifo = &sc->rxfifo;
	bzero(fifo, sizeof(struct fifo));
	fifo->size = size;

	if (sc->tty.opened) {
		/*
		 * Flush any unread input from the tty buffer.
		 */
		while (1) {
			nread = read(sc->tty.rfd, flushbuf, sizeof(flushbuf));
			if (nread != sizeof(flushbuf))
				break;
		}

		/*
		 * Enable mevent to trigger when new characters are available
		 * on the tty fd.
		 */
		error = mevent_enable(sc->mev);
		assert(error == 0);
	}
}

static int
rxfifo_available(struct uart_backend *sc)
{
	struct fifo *fifo;

	fifo = &sc->rxfifo;
	return (fifo->num < fifo->size);
}

static int
rxfifo_putchar(struct uart_backend *sc, uint8_t ch)
{
	struct fifo *fifo;
	int error;

	fifo = &sc->rxfifo;

	if (fifo->num < fifo->size) {
		fifo->buf[fifo->windex] = ch;
		fifo->windex = (fifo->windex + 1) % fifo->size;
		fifo->num++;
		if (!rxfifo_available(sc)) {
			if (sc->tty.opened) {
				/*
				 * Disable mevent callback if the FIFO is full.
				 */
				error = mevent_disable(sc->mev);
				assert(error == 0);
			}
		}
		return (0);
	} else
		return (-1);
}

int
uart_rxfifo_getchar(struct uart_backend *sc)
{
	struct fifo *fifo;
	int c, error, wasfull;

	wasfull = 0;
	fifo = &sc->rxfifo;
	if (fifo->num > 0) {
		if (!rxfifo_available(sc))
			wasfull = 1;
		c = fifo->buf[fifo->rindex];
		fifo->rindex = (fifo->rindex + 1) % fifo->size;
		fifo->num--;
		if (wasfull) {
			if (sc->tty.opened) {
				error = mevent_enable(sc->mev);
				assert(error == 0);
			}
		}
		return (c);
	} else
		return (-1);
}

int
uart_rxfifo_numchars(struct uart_backend *sc)
{
	struct fifo *fifo = &sc->rxfifo;

	return (fifo->num);
}

void
uart_rxfifo_drain(struct uart_backend *b, bool loopback)
{
	int ch;

	if (loopback) {
		(void) ttyread(&b->tty);
	} else {
		while (rxfifo_available(b) &&
		    ((ch = ttyread(&b->tty)) != -1)) {
			rxfifo_putchar(b, ch);
		}
	}
}

bool
uart_rxfifo_write(struct uart_backend *b, bool loopback, uint8_t ch)
{
	if (loopback) {
		if (rxfifo_putchar(b, ch) != 0)
			return (false);
	} else if (b->tty.opened) {
		ttywrite(&b->tty, ch);
	} /* else drop on floor */

	return (true);
}

static void
uart_opentty(struct uart_backend *sc, void (*func)(int, enum ev_type, void *),
    void *arg)
{

	ttyopen(&sc->tty);
	sc->mev = mevent_add(sc->tty.rfd, EVF_READ, func, arg);
	assert(sc->mev != NULL);
}

static int
uart_stdio_backend(struct uart_backend *sc)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
#endif

	if (uart_stdio)
		return (-1);

	sc->tty.rfd = STDIN_FILENO;
	sc->tty.wfd = STDOUT_FILENO;
	sc->tty.opened = true;

	if (fcntl(sc->tty.rfd, F_SETFL, O_NONBLOCK) != 0)
		return (-1);
	if (fcntl(sc->tty.wfd, F_SETFL, O_NONBLOCK) != 0)
		return (-1);

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_IOCTL, CAP_READ);
	if (caph_rights_limit(sc->tty.rfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(sc->tty.rfd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	uart_stdio = true;

	return (0);
}

static int
uart_tty_backend(struct uart_backend *sc, const char *path)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
#endif
	int fd;

	fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0)
		return (-1);

	if (!isatty(fd)) {
		close(fd);
		return (-1);
	}

	sc->tty.rfd = sc->tty.wfd = fd;
	sc->tty.opened = true;

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_IOCTL, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(fd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	return (0);
}

struct uart_backend *
uart_backend_alloc(void)
{
	struct uart_backend *b;

	b = calloc(1, sizeof(struct uart_backend));
	assert(b != NULL);

	return (b);
}

int
uart_backend_open(struct uart_backend *b, const char *device,
    void (*func)(int, enum ev_type, void *), void *arg)
{
	int retval;

	if (device == NULL)
		return (0);

	if (strcmp("stdio", device) == 0)
		retval = uart_stdio_backend(b);
	else
		retval = uart_tty_backend(b, device);
	if (retval == 0)
		uart_opentty(b, func, arg);

	return (retval);
}

#ifdef BHYVE_SNAPSHOT
int
uart_backend_snapshot(struct uart_backend *b, struct vm_snapshot_meta *meta)
{
	int ret;

	SNAPSHOT_VAR_OR_LEAVE(b->rxfifo.rindex, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(b->rxfifo.windex, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(b->rxfifo.num, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(b->rxfifo.size, meta, ret, done);
	SNAPSHOT_BUF_OR_LEAVE(b->rxfifo.buf, sizeof(sc->rxfifo.buf),
			      meta, ret, done);

done:
	return (ret);
}
#endif
