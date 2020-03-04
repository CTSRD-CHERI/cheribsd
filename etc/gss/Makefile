# $FreeBSD$

.include <src.opts.mk>

FILES=	mech qop
FILESDIR= /etc/gss

.ifdef COMPAT_CHERI
GSS_LIBDIR= /usr/libcheri
.else
GSS_LIBDIR= /usr/lib
.endif

mech: mech.in
	sed -e 's,@LIBDIR@,${GSS_LIBDIR},' < ${.OODATE} > ${.TARGET}

.include <bsd.prog.mk>
