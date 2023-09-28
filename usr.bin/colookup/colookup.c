/*-
 * Copyright (c) 2022 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the CHERI for Hypervisors and Operating Systems
 * (CHaOS) project, funded by EPSRC grant EP/V000292/1.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/auxv.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool vflag = false;

static void
usage(void)
{

	fprintf(stderr,
	    "usage: colookup -c name\n"
	    "       colookup -f path -i index [-f path -i index ...] command [args ...]\n"
	    "       colookup -n name -i index [-n name -i index ...] command [args ...]\n"
	    "       colookup -s\n");
	exit(0);
}

static void * __capability
receive_cap(char *filename)
{
	void * __capability target;
	struct msghdr msg;
	union {
		struct cmsghdr	hdr;
		unsigned char	buf[CMSG_SPACE(sizeof(target))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct sockaddr_un sun;
	ssize_t received;
	int fd, error;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, filename, sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);

	error = connect(fd, (struct sockaddr *)&sun, sizeof(sun));
	if (error != 0)
		err(1, "%s", filename);

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);
	msg.msg_iov = NULL;
	msg.msg_iovlen = 0;

	received = recvmsg(fd, &msg, MSG_WAITALL);
	if (received != 0) {
		if (errno == EPROT)
			warnx("likely not colocated with coregister(1)");
		err(1, "%s: recvmsg", filename);
	}
	if (msg.msg_flags & MSG_TRUNC)
		errx(1, "%s: message truncated", filename);
	if (msg.msg_flags & MSG_CTRUNC)
		errx(1, "%s: control message truncated", filename);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL)
		errx(1, "%s: CMSG_FIRSTHDR returned NULL", filename);
	if (cmsg->cmsg_len != CMSG_LEN(sizeof(target)))
		errx(1, "%s: received wrong cmsg_len %d, expected %lu\n", filename, cmsg->cmsg_len, CMSG_LEN(sizeof(target)));
	if (cmsg->cmsg_level != SOL_SOCKET)
		errx(1, "%s: received wrong cmsg_level %d, expected %d\n", filename, cmsg->cmsg_level, SOL_SOCKET);
	if (cmsg->cmsg_type != SCM_CAPS)
		errx(1, "%s: received wrong cmsg_type %d, expected %d\n", filename, cmsg->cmsg_type, SCM_CAPS);
	memcpy(&target, CMSG_DATA(cmsg), sizeof(target));

	error = close(fd);
	if (error != 0)
		warn("close");

	return (target);
}

static void
consider(int *capcp, void * __capability **capvp, int *chosenp,
    char **namep, char **filenamep)
{
	void * __capability lookedup;
	int error;

	if (*chosenp < 0)
		return;

	if (*filenamep != NULL && *namep != NULL)
		errx(-1, "-f and -n are mutually exclusive");

	if (*namep != NULL) {
		error = colookup(*namep, &lookedup);
		if (error != 0)
			err(1, "%s", *namep);
		if (vflag) {
			printf("%s: %d: colookedup %#lp from %s\n",
			    getprogname(), *chosenp, lookedup, *namep);
		}
	} else if (*filenamep != NULL) {
		lookedup = receive_cap(*filenamep);
		if (vflag) {
			printf("%s: %d: received %#lp from %s\n",
			    getprogname(), *chosenp, lookedup, *filenamep);
		}
	} else {
		return;
	}

	error = capvset(capcp, capvp, *chosenp, lookedup);
	if (error != 0)
		err(1, "capvset");

	*chosenp = -1;
	*namep = NULL;
	*filenamep = NULL;
}

int
main(int argc, char **argv)
{
	void * __capability *capv;
	void * __capability lookedup;
	void * __capability code;
	void * __capability data;
	char *tmp = NULL, *name = NULL, *filename = NULL;
	int capc, ch, chosen = -1, error;

	capvfetch(&capc, &capv);

	while ((ch = getopt(argc, argv, "c:f:i:n:sv")) != -1) {
		switch (ch) {
		case 'c':
			error = colookup(optarg, &lookedup);
			if (error != 0)
				err(1, "%s", optarg);
			printf("%s: %#lp\n", optarg, lookedup);
			return (0);
		case 'f':
			if (filename != NULL)
				errx(-1, "-f specified more than once");
			filename = optarg;
			consider(&capc, &capv, &chosen, &name, &filename);
			break;
		case 'i':
			if (chosen >= 0)
				errx(-1, "-i specified more than once");
			chosen = strtol(optarg, &tmp, 10);
			if (*tmp != '\0')
				errx(1, "argument to -i must be a number");
			if (chosen < 0)
				usage();
			consider(&capc, &capv, &chosen, &name, &filename);
			break;
		case 'n':
			if (name != NULL)
				errx(-1, "-n specified more than once");
			name = optarg;
			consider(&capc, &capv, &chosen, &name, &filename);
			break;
		case 's':
			error = _cosetup(COSETUP_COCALL, &code, &data);
			if (error != 0)
				err(1, "cosetup");
			printf("cocall %#lp, %#lp\n", code, data);
			error = _cosetup(COSETUP_COACCEPT, &code, &data);
			if (error != 0)
				err(1, "cosetup");
			printf("coaccept %#lp, %#lp\n", code, data);
			return (0);
		case 'v':
			vflag = true;
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1 || chosen >= 0 || name != NULL | filename != NULL)
		usage();

	coexecvpc(getppid(), argv[0], argv, capv, capc);
	err(1, "%s", argv[0]);
}
