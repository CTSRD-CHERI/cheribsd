.include <src.opts.mk>

PACKAGE=	bhyve
FILESDIR=	${SHAREDIR}/bhyve/gdb

FILES+=		target.xml

.if ${MACHINE_ARCH} == "amd64"
XMLARCH=	i386:x86-64
FILES+=		amd64.xml
.elif ${MACHINE_ARCH} == "aarch64" || ${MACHINE_ARCH} == "aarch64c"
XMLARCH=	aarch64
FILES+=		aarch64-core.xml
.if ${MACHINE_ARCH} == "aarch64c"
FILES+=		aarch64-capability.xml
.endif
.endif

.if !make(install*)
target.xml: .PHONY
	@echo "<?xml version=\"1.0\"?>" > ${.TARGET}
	@echo "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">" >> ${.TARGET}
	@echo "<target>" >> ${.TARGET}
	@echo "  <architecture>${XMLARCH}</architecture>" >> ${.TARGET}
.for file in ${FILES:Ntarget.xml}
	@echo "  <xi:include href=\"${file}\"/>" >> ${.TARGET}
.endfor
	@echo "</target>" >> ${.TARGET}
.endif

.include <bsd.prog.mk>
