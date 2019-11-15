# $FreeBSD$

.if !target(__<bsd.init.mk>__)
.error bsd.links.mk cannot be included directly.
.endif

.if defined(NO_ROOT)
.if !defined(TAGS) || ! ${TAGS:Mpackage=*}
TAGS+=         package=${PACKAGE}
.endif
TAG_ARGS=      -T ${TAGS:[*]:S/ /,/g}
.endif

afterinstall: _installlinks
.ORDER: realinstall _installlinks
_installlinks:
.for s t in ${LINKS}
	# Don't delete the source file on a case-insensitive file-system and pass -S
	# to install to avoid overwriting the source
.if ${s:tl} == ${t:tl}
	if test "${DESTDIR}${t}" -ef "${DESTDIR}${s}"; then \
		echo "Note: installing man link from ${l} to ${t} on case-insensitive file system."; \
	fi
	${INSTALL_LINK} -S ${TAG_ARGS} ${DESTDIR}${s} ${DESTDIR}${t}
.else
	${INSTALL_LINK} ${TAG_ARGS} ${DESTDIR}${s} ${DESTDIR}${t}
.endif
.endfor
.for s t in ${SYMLINKS}
	${INSTALL_SYMLINK} ${TAG_ARGS} ${s} ${DESTDIR}${t}
.endfor
