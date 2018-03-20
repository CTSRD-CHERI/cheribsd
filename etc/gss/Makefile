# $FreeBSD$

.include <src.opts.mk>

FILES=	mech qop
NO_OBJ=
FILESDIR= /etc/gss

.if ${MK_CHERI_PURE} == "yes"
GSS_LIBDIR= /usr/libcheri
.else
GSS_LIBDIR= /usr/lib
.endif

mech: mech.in
	sed -e 's,@LIBDIR@,${GSS_LIBDIR},' < ${.OODATE} > ${.TARGET}

.include <bsd.prog.mk>
