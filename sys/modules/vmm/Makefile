# $FreeBSD$

.include <kmod.opts.mk>

KMOD=	vmm

SRCS=	opt_acpi.h opt_ddb.h device_if.h bus_if.h pci_if.h pcib_if.h acpi_if.h

CFLAGS+= -DVMM_KEEP_STATS
CFLAGS+= -I${SRCTOP}/sys/${MACHINE}/vmm
CFLAGS+= -I${SRCTOP}/sys/${MACHINE}/vmm/io

# generic vmm support
.PATH: ${SRCTOP}/sys/${MACHINE}/vmm
SRCS+=	vmm.c		\
	vmm_dev.c	\
	vmm_instruction_emul.c	\
	vmm_mem.c	\
	vmm_stat.c

.if ${MACHINE_CPUARCH} == "aarch64"
# TODO: Add the new EL2 code
SRCS+=	vmm_arm64.c \
	vmm_psci.c \
	vmm_reset.c \
	vmm_call.S \
	vmm_mmu.c \
	vmm_hyp_el2.S

.PATH: ${SRCTOP}/sys/${MACHINE}/vmm/io
SRCS+=	vgic_v3.c \
	vtimer.c

CLEANFILES+=	vmm_hyp_exception.o vmm_hyp.o vmm_hyp_blob.elf.full
CLEANFILES+=	vmm_hyp_blob.elf vmm_hyp_blob.bin

CFLAGS.vmm_hyp_exception.S += -fpie
CFLAGS.vmm_hyp.c += -fpie
vmm_hyp_exception.o:	vmm_hyp_exception.S
vmm_hyp.o: vmm_hyp.c

vmm_hyp_blob.elf.full:	vmm_hyp_exception.o vmm_hyp.o
	${CC} -o ${.TARGET} ${.ALLSRC} -fPIE -nostdlib \
	    -T ${SYSDIR}/conf/ldscript.arm64 \
	    -Wl,--defsym=text_start='0x0'

vmm_hyp_blob.elf:	vmm_hyp_blob.elf.full
	${OBJCOPY} --strip-debug ${.ALLSRC} ${.TARGET}

vmm_hyp_blob.bin:	vmm_hyp_blob.elf
	${OBJCOPY} --output-target=binary ${.ALLSRC} ${.TARGET}

vmm_hyp_el2.o:	vmm_hyp_blob.bin

.elif ${MACHINE_CPUARCH} == "amd64"
DPSRCS+=	vmx_assym.h svm_assym.h
DPSRCS+=	vmx_genassym.c svm_genassym.c offset.inc

CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/intel
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/amd

SRCS+=	vmm_host.c	\
	vmm_ioport.c	\
	vmm_lapic.c	\
	vmm_util.c	\
	x86.c

.PATH: ${SRCTOP}/sys/${MACHINE}/vmm/io
SRCS+=	iommu.c		\
	ppt.c           \
	vatpic.c	\
	vatpit.c	\
	vhpet.c		\
	vioapic.c	\
	vlapic.c	\
	vpmtmr.c	\
	vrtc.c

# intel-specific files
.PATH: ${SRCTOP}/sys/amd64/vmm/intel
SRCS+=	ept.c		\
	vmcs.c		\
	vmx_msr.c	\
	vmx_support.S	\
	vmx.c		\
	vtd.c

# amd-specific files
.PATH: ${SRCTOP}/sys/amd64/vmm/amd
SRCS+=	vmcb.c		\
	amdiommu.c	\
	ivhd_if.c	\
	ivhd_if.h	\
	svm.c		\
	svm_support.S	\
	npt.c		\
	ivrs_drv.c	\
	amdvi_hw.c	\
	svm_msr.c

.if ${KERN_OPTS:MBHYVE_SNAPSHOT} != ""
SRCS+=	vmm_snapshot.c
.endif

CLEANFILES+=	vmx_assym.h vmx_genassym.o svm_assym.h svm_genassym.o

OBJS_DEPEND_GUESS.vmx_support.o+= vmx_assym.h
OBJS_DEPEND_GUESS.svm_support.o+= svm_assym.h
.endif

vmx_assym.h:    vmx_genassym.o
	sh ${SYSDIR}/kern/genassym.sh vmx_genassym.o > ${.TARGET}

svm_assym.h:    svm_genassym.o
	sh ${SYSDIR}/kern/genassym.sh svm_genassym.o > ${.TARGET}

vmx_support.o:
	${CC} -c -x assembler-with-cpp -DLOCORE ${CFLAGS} \
	    ${.IMPSRC} -o ${.TARGET}

svm_support.o:
	${CC} -c -x assembler-with-cpp -DLOCORE ${CFLAGS} \
	    ${.IMPSRC} -o ${.TARGET}

hyp_genassym.o: offset.inc
	${CC} -c ${CFLAGS:N-flto:N-fno-common} -fcommon ${.IMPSRC}

vmx_genassym.o: offset.inc
	${CC} -c ${CFLAGS:N-flto:N-fno-common} -fcommon ${.IMPSRC}

svm_genassym.o: offset.inc
	${CC} -c ${CFLAGS:N-flto:N-fno-common} -fcommon ${.IMPSRC}

.include <bsd.kmod.mk>
