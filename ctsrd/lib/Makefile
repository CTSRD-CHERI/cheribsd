# $FreeBSD$

.include <src.opts.mk>

SUBDIR_ORDERED=	libvuln_png

SUBDIR=	${SUBDIR_ORDERED} \
	libterasic_mtl

.if ${MK_FILE} != "no"
SUBDIR+= libvuln_magic
.endif

.if defined(LIBCHERI)
SUBDIR:=	libvuln_png
.endif

.include <bsd.subdir.mk>
