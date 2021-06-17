#
# $FreeBSD$
#

.include <src.opts.mk>
CFLAGS+=-I${.CURDIR}/../../contrib/lib9p
CFLAGS+=-I${SRCTOP}/sys
.PATH:  ${SRCTOP}/sys/cam/ctl

PROG=	bhyve
PACKAGE=	bhyve

MAN=	bhyve.8 bhyve_config.5

BHYVE_SYSDIR?=${SRCTOP}

SRCS=	\
	acpi.c			\
	audio.c			\
	bhyvegc.c		\
	bhyverun.c		\
	block_if.c		\
	bootrom.c		\
	config.c		\
	console.c		\
	ctl_util.c		\
	ctl_scsi_all.c		\
	hda_codec.c		\
	mem.c			\
	mevent.c		\
	net_backends.c		\
	net_utils.c		\
	pci_ahci.c		\
	pci_e82545.c		\
	pci_emul.c		\
	pci_hda.c		\
	pci_hostbridge.c	\
	pci_nvme.c		\
	pci_virtio_9p.c		\
	pci_virtio_block.c	\
	pci_virtio_console.c	\
	pci_virtio_input.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_virtio_scsi.c	\
	pci_uart.c		\
	pci_xhci.c		\
	post.c			\
	smbiostbl.c		\
	sockstream.c		\
	uart_backend.c		\
	usb_emul.c		\
	usb_mouse.c		\
	virtio.c		\
	vmgenc.c		\
	iov.c

.if ${MACHINE_CPUARCH} == "aarch64"
# Missing vm_get_ioctls
CFLAGS+=	-DWITHOUT_CAPSICUM
LIBFDTSRCDIR=	${SRCTOP}/sys/contrib/libfdt
CFLAGS+=	-I${LIBFDTSRCDIR}
LIBADD+=		fdt
SRCS+=	\
	bootcode.c		\
	fdt.c			\
	mmio_uart.c		\
	pl011.c
.endif

.if ${MACHINE_CPUARCH} == "amd64"
SRCS+=	\
	atkbdc.c		\
	consport.c		\
	dbgport.c		\
	fwctl.c			\
	gdb.c			\
	inout.c			\
	ioapic.c		\
	kernemu_dev.c		\
	mptbl.c			\
	pci_fbuf.c		\
	pci_irq.c		\
	pci_lpc.c		\
	pci_passthru.c		\
	pctestdev.c		\
	pm.c			\
	ps2kbd.c		\
	ps2mouse.c		\
	rfb.c			\
	rtc.c			\
	task_switch.c		\
	uart_emul.c		\
	xmsr.c			\
	spinup_ap.c		\
	vga.c			\

.endif

.if ${MK_BHYVE_SNAPSHOT} != "no"
SRCS+=	snapshot.c
.endif

CFLAGS.kernemu_dev.c+=	-I${SRCTOP}/sys/amd64

.PATH:  ${BHYVE_SYSDIR}/sys/${MACHINE}/vmm
SRCS+=	vmm_instruction_emul.c

LIBADD+=vmmapi md nv pthread z util sbuf cam 9p

.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_pwd
LIBADD+=	cap_grp
# Temporary disable capsicum, until we integrate checkpoint code with it.
#CFLAGS+=-DWITH_CASPER
.endif

.if ${MK_BHYVE_SNAPSHOT} != "no"
LIBADD+= ucl xo
.endif

.if ${MK_INET_SUPPORT} != "no"
CFLAGS+=-DINET
.endif
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+=-DINET6
.endif
.if ${MK_NETGRAPH_SUPPORT} != "no"
CFLAGS+=-DNETGRAPH
LIBADD+=    netgraph
.endif
.if ${MK_OPENSSL} == "no"
CFLAGS+=-DNO_OPENSSL
.else
LIBADD+=	crypto
.endif

CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/e1000
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/mii
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/usb/controller
.if ${MK_BHYVE_SNAPSHOT} != "no"
CFLAGS+= -I${SRCTOP}/contrib/libucl/include

# Temporary disable capsicum, until we integrate checkpoint code with it.
CFLAGS+= -DWITHOUT_CAPSICUM

CFLAGS+= -DBHYVE_SNAPSHOT
.endif

.ifdef GDB_LOG
CFLAGS+=-DGDB_LOG
.endif

WARNS?=	2

SUBDIR=	kbdlayout
.include <bsd.prog.mk>
