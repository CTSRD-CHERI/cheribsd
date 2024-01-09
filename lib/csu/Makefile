
.include <src.opts.mk>

.if exists(${.CURDIR}/${MACHINE_ARCH:S/aarch64cb/aarch64c/:S/powerpc64le/powerpc64/})
SUBDIR+= ${MACHINE_ARCH:S/aarch64cb/aarch64c/:S/powerpc64le/powerpc64/}
. if exists(${.CURDIR}/${MACHINE_ARCH:S/aarch64cb/aarch64c/:S/powerpc64le/powerpc64/}_p128)
SUBDIR+= ${MACHINE_ARCH:S/aarch64cb/aarch64c/:S/powerpc64le/powerpc64/}_p128
SUBDIR+= ${MACHINE_ARCH:S/aarch64cb/aarch64c/:S/powerpc64le/powerpc64/}_p128g
. endif
.else
SUBDIR+= ${MACHINE_CPUARCH}
. if exists(${.CURDIR}/${MACHINE_CPUARCH}_p128)
SUBDIR+= ${MACHINE_CPUARCH}_p128
SUBDIR+= ${MACHINE_CPUARCH}_p128g
. endif
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.subdir.mk>
