# $FreeBSD$

.if ${MACHINE_ARCH:Mmips64*c*}
NO_SHARED=	faults during test runs
.endif

CONFS=	crontab
PROG=	cron
MAN=	cron.8
SRCS=	cron.c database.c do_command.c job.c user.c popen.c

CFLAGS+= -DLOGIN_CAP -DPAM

LIBADD=	cron pam util

WARNS?=	2

.include <bsd.prog.mk>
