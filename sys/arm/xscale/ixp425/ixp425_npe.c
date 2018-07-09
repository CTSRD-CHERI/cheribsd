/*-
 * SPDX-License-Identifier: (BSD-2-Clause-FreeBSD AND BSD-3-Clause)
 *
 * Copyright (c) 2006-2008 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

/*-
 * Copyright (c) 2001-2005, Intel Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
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

/*
 * Intel XScale Network Processing Engine (NPE) support.
 *
 * Each NPE has an ixpnpeX device associated with it that is
 * attached at boot.  Depending on the microcode loaded into
 * an NPE there may be an Ethernet interface (npeX) or some
 * other network interface (e.g. for ATM).  This file has support
 * for loading microcode images and the associated NPE CPU
 * manipulations (start, stop, reset).
 *
 * The code here basically replaces the npeDl and npeMh classes
 * in the Intel Access Library (IAL).
 *
 * NB: Microcode images are loaded with firmware(9).  To
 *     include microcode in a static kernel include the
 *     ixpnpe_fw device.  Otherwise the firmware will be
 *     automatically loaded from the filesystem.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/time.h>
#include <sys/bus.h>
#include <sys/resource.h>
#include <sys/rman.h>
#include <sys/sysctl.h>

#include <sys/linker.h>
#include <sys/firmware.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <machine/intr.h>
#include <arm/xscale/ixp425/ixp425reg.h>
#include <arm/xscale/ixp425/ixp425var.h>

#include <arm/xscale/ixp425/ixp425_npereg.h>
#include <arm/xscale/ixp425/ixp425_npevar.h>

struct ixpnpe_softc {
	device_t	sc_dev;
	bus_space_tag_t	sc_iot;
	bus_space_handle_t sc_ioh;
	bus_size_t	sc_size;	/* size of mapped register window */
	struct resource	*sc_irq;	/* IRQ resource */
	void		*sc_ih;		/* interrupt handler */
	struct mtx	sc_mtx;		/* mailbox lock */
	uint32_t	sc_msg[2];	/* reply msg collected in ixpnpe_intr */
	int		sc_msgwaiting;	/* sc_msg holds valid data */
	int		sc_npeid;
	int		sc_nrefs;	/* # of references */

	int		validImage;	/* valid ucode image loaded */
	int		started;	/* NPE is started */
	uint8_t		functionalityId;/* ucode functionality ID */
	int		insMemSize;	/* size of instruction memory */
	int		dataMemSize;	/* size of data memory */
	uint32_t	savedExecCount;
	uint32_t	savedEcsDbgCtxtReg2;
};
static struct ixpnpe_softc *npes[NPE_MAX];

#define	IX_NPEDL_NPEIMAGE_FIELD_MASK	0xff

/* used to read download map from version in microcode image */
#define IX_NPEDL_BLOCK_TYPE_INSTRUCTION	0x00000000
#define IX_NPEDL_BLOCK_TYPE_DATA	0x00000001
#define IX_NPEDL_BLOCK_TYPE_STATE	0x00000002
#define IX_NPEDL_END_OF_DOWNLOAD_MAP	0x0000000F

/*
 * masks used to extract address info from State information context
 * register addresses as read from microcode image
 */
#define IX_NPEDL_MASK_STATE_ADDR_CTXT_REG         0x0000000F
#define IX_NPEDL_MASK_STATE_ADDR_CTXT_NUM         0x000000F0

/* LSB offset of Context Number field in State-Info Context Address */
#define IX_NPEDL_OFFSET_STATE_ADDR_CTXT_NUM       4

/* size (in words) of single State Information entry (ctxt reg address|data) */
#define IX_NPEDL_STATE_INFO_ENTRY_SIZE	2

typedef struct {
	uint32_t type;
	uint32_t offset;
} IxNpeDlNpeMgrDownloadMapBlockEntry;

typedef union {
	IxNpeDlNpeMgrDownloadMapBlockEntry block;
	uint32_t eodmMarker;
} IxNpeDlNpeMgrDownloadMapEntry;

typedef struct {
	/* 1st entry in the download map (there may be more than one) */
	IxNpeDlNpeMgrDownloadMapEntry entry[1];
} IxNpeDlNpeMgrDownloadMap;

/* used to access an instruction or data block in a microcode image */
typedef struct {
	uint32_t npeMemAddress;
	uint32_t size;
	uint32_t data[1];
} IxNpeDlNpeMgrCodeBlock;

/* used to access each Context Reg entry state-information block */
typedef struct {
	uint32_t addressInfo;
	uint32_t value;
} IxNpeDlNpeMgrStateInfoCtxtRegEntry;

/* used to access a state-information block in a microcode image */
typedef struct {
	uint32_t size;
	IxNpeDlNpeMgrStateInfoCtxtRegEntry ctxtRegEntry[1];
} IxNpeDlNpeMgrStateInfoBlock;

static int npe_debug = 0;
SYSCTL_INT(_debug, OID_AUTO, ixp425npe, CTLFLAG_RWTUN, &npe_debug,
	   0, "IXP4XX NPE debug msgs");
#define	DPRINTF(dev, fmt, ...) do {					\
	if (npe_debug) device_printf(dev, fmt, __VA_ARGS__);		\
} while (0)
#define	DPRINTFn(n, dev, fmt, ...) do {					\
	if (npe_debug >= n) printf(fmt, __VA_ARGS__);			\
} while (0)

static int npe_checkbits(struct ixpnpe_softc *, uint32_t reg, uint32_t);
static int npe_isstopped(struct ixpnpe_softc *);
static int npe_load_ins(struct ixpnpe_softc *,
		const IxNpeDlNpeMgrCodeBlock *bp, int verify);
static int npe_load_data(struct ixpnpe_softc *,
		const IxNpeDlNpeMgrCodeBlock *bp, int verify);
static int npe_load_stateinfo(struct ixpnpe_softc *,
		const IxNpeDlNpeMgrStateInfoBlock *bp, int verify);
static int npe_load_image(struct ixpnpe_softc *,
		const uint32_t *imageCodePtr, int verify);
static int npe_cpu_reset(struct ixpnpe_softc *);
static int npe_cpu_start(struct ixpnpe_softc *);
static int npe_cpu_stop(struct ixpnpe_softc *);
static void npe_cmd_issue_write(struct ixpnpe_softc *,
		uint32_t cmd, uint32_t addr, uint32_t data);
static uint32_t npe_cmd_issue_read(struct ixpnpe_softc *,
		uint32_t cmd, uint32_t addr);
static int npe_ins_write(struct ixpnpe_softc *,
		uint32_t addr, uint32_t data, int verify);
static int npe_data_write(struct ixpnpe_softc *,
		uint32_t addr, uint32_t data, int verify);
static void npe_ecs_reg_write(struct ixpnpe_softc *,
		uint32_t reg, uint32_t data);
static uint32_t npe_ecs_reg_read(struct ixpnpe_softc *, uint32_t reg);
static void npe_issue_cmd(struct ixpnpe_softc *, uint32_t command);
static void npe_cpu_step_save(struct ixpnpe_softc *);
static int npe_cpu_step(struct ixpnpe_softc *, uint32_t npeInstruction,
		uint32_t ctxtNum, uint32_t ldur);
static void npe_cpu_step_restore(struct ixpnpe_softc *);
static int npe_logical_reg_read(struct ixpnpe_softc *,
		uint32_t regAddr, uint32_t regSize,
		uint32_t ctxtNum, uint32_t *regVal);
static int npe_logical_reg_write(struct ixpnpe_softc *,
		uint32_t regAddr, uint32_t regVal,
		uint32_t regSize, uint32_t ctxtNum, int verify);
static int npe_physical_reg_write(struct ixpnpe_softc *,
		uint32_t regAddr, uint32_t regValue, int verify);
static int npe_ctx_reg_write(struct ixpnpe_softc *, uint32_t ctxtNum,
		uint32_t ctxtReg, uint32_t ctxtRegVal, int verify);

static void ixpnpe_intr(void *arg);

static uint32_t
npe_reg_read(struct ixpnpe_softc *sc, bus_size_t off)
{
	uint32_t v = bus_space_read_4(sc->sc_iot, sc->sc_ioh, off);
	DPRINTFn(9, sc->sc_dev, "%s(0x%lx) => 0x%x\n", __func__, off, v);
	return v;
}

static void
npe_reg_write(struct ixpnpe_softc *sc, bus_size_t off, uint32_t val)
{
	DPRINTFn(9, sc->sc_dev, "%s(0x%lx, 0x%x)\n", __func__, off, val);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, off, val);
}

struct ixpnpe_softc *
ixpnpe_attach(device_t dev, int npeid)
{
	struct npeconfig {
		uint32_t	base;
		uint32_t	size;
		int		irq;
		uint32_t	ins_memsize;
		uint32_t	data_memsize;
	};
	static const struct npeconfig npeconfigs[NPE_MAX] = {
		[NPE_A] = {
		    .base = IXP425_NPE_A_HWBASE,
		    .size = IXP425_NPE_A_SIZE,
		    .irq = IXP425_INT_NPE_A,
		    .ins_memsize = IX_NPEDL_INS_MEMSIZE_WORDS_NPEA,
		    .data_memsize = IX_NPEDL_DATA_MEMSIZE_WORDS_NPEA
		},
		[NPE_B] = {
		    .base = IXP425_NPE_B_HWBASE,
		    .size = IXP425_NPE_B_SIZE,
		    .irq = IXP425_INT_NPE_B,
		    .ins_memsize = IX_NPEDL_INS_MEMSIZE_WORDS_NPEB,
		    .data_memsize = IX_NPEDL_DATA_MEMSIZE_WORDS_NPEB
		},
		[NPE_C] = {
		    .base = IXP425_NPE_C_HWBASE,
		    .size = IXP425_NPE_C_SIZE,
		    .irq = IXP425_INT_NPE_C,
		    .ins_memsize = IX_NPEDL_INS_MEMSIZE_WORDS_NPEC,
		    .data_memsize = IX_NPEDL_DATA_MEMSIZE_WORDS_NPEC
		},
	};
	struct ixp425_softc *sa = device_get_softc(device_get_parent(dev));
	struct ixpnpe_softc *sc;
	const struct npeconfig *config;
	int rid;

	if (npeid >= NPE_MAX) {
		device_printf(dev, "%s: bad npeid %d\n", __func__, npeid);
		return NULL;
	}
	sc = npes[npeid];
	if (sc != NULL) {
		sc->sc_nrefs++;
		return sc;
	}
	config = &npeconfigs[npeid];

	/* XXX M_BUS */
	sc = malloc(sizeof(struct ixpnpe_softc), M_TEMP, M_WAITOK | M_ZERO);
	sc->sc_dev = dev;
	sc->sc_iot = sa->sc_iot;
	mtx_init(&sc->sc_mtx, device_get_nameunit(dev), "npe driver", MTX_DEF);
	sc->sc_npeid = npeid;
	sc->sc_nrefs = 1;

	sc->sc_size = config->size;
	if (cpu_is_ixp42x()) {
		/* NB: instruction/data memory sizes are NPE-dependent */
		sc->insMemSize = config->ins_memsize;
		sc->dataMemSize = config->data_memsize;
	} else {
		sc->insMemSize = IXP46X_NPEDL_INS_MEMSIZE_WORDS;
		sc->dataMemSize = IXP46X_NPEDL_DATA_MEMSIZE_WORDS;
	}

	if (bus_space_map(sc->sc_iot, config->base, sc->sc_size, 0, &sc->sc_ioh))
		panic("%s: Cannot map registers", device_get_name(dev));

	/*
	 * Setup IRQ and handler for NPE message support.
	 */
	rid = 0;
	sc->sc_irq = bus_alloc_resource(dev, SYS_RES_IRQ, &rid,
	    config->irq, config->irq, 1, RF_ACTIVE);
	if (sc->sc_irq == NULL)
		panic("%s: Unable to allocate irq %u", device_get_name(dev),
		    config->irq);
	/* XXX could be a source of entropy */
	bus_setup_intr(dev, sc->sc_irq, INTR_TYPE_NET | INTR_MPSAFE,
	    NULL, ixpnpe_intr, sc, &sc->sc_ih);
	/*
	 * Enable output fifo interrupts (NB: must also set OFIFO Write Enable)
	 */
	npe_reg_write(sc, IX_NPECTL,
	    npe_reg_read(sc, IX_NPECTL) | (IX_NPECTL_OFE | IX_NPECTL_OFWE));

	npes[npeid] = sc;

	return sc;
}

void
ixpnpe_detach(struct ixpnpe_softc *sc)
{
	if (--sc->sc_nrefs == 0) {
		npes[sc->sc_npeid] = NULL;

		/* disable output fifo interrupts */
		npe_reg_write(sc, IX_NPECTL,
		    npe_reg_read(sc, IX_NPECTL) &~ (IX_NPECTL_OFE | IX_NPECTL_OFWE));

		bus_teardown_intr(sc->sc_dev, sc->sc_irq, sc->sc_ih);
		bus_space_unmap(sc->sc_iot, sc->sc_ioh, sc->sc_size);
		mtx_destroy(&sc->sc_mtx);
		free(sc, M_TEMP);
	}
}

int
ixpnpe_stopandreset(struct ixpnpe_softc *sc)
{
	int error;

	mtx_lock(&sc->sc_mtx);
	error = npe_cpu_stop(sc);		/* stop NPE */
	if (error == 0)
		error = npe_cpu_reset(sc);	/* reset it */
	if (error == 0)
		sc->started = 0;		/* mark stopped */
	mtx_unlock(&sc->sc_mtx);

	DPRINTF(sc->sc_dev, "%s: error %d\n", __func__, error);
	return error;
}

static int
ixpnpe_start_locked(struct ixpnpe_softc *sc)
{
	int error;

	if (!sc->started) {
		error = npe_cpu_start(sc);
		if (error == 0)
			sc->started = 1;
	} else
		error = 0;

	DPRINTF(sc->sc_dev, "%s: error %d\n", __func__, error);
	return error;
}

int
ixpnpe_start(struct ixpnpe_softc *sc)
{
	int ret;

	mtx_lock(&sc->sc_mtx);
	ret = ixpnpe_start_locked(sc);
	mtx_unlock(&sc->sc_mtx);
	return (ret);
}

int
ixpnpe_stop(struct ixpnpe_softc *sc)
{
	int error;

	mtx_lock(&sc->sc_mtx);
	error = npe_cpu_stop(sc);
	if (error == 0)
		sc->started = 0;
	mtx_unlock(&sc->sc_mtx);

	DPRINTF(sc->sc_dev, "%s: error %d\n", __func__, error);
	return error;
}

/*
 * Indicates the start of an NPE Image, in new NPE Image Library format.
 * 2 consecutive occurrences indicates the end of the NPE Image Library
 */
#define NPE_IMAGE_MARKER 0xfeedf00d

/*
 * NPE Image Header definition, used in new NPE Image Library format
 */
typedef struct {
	uint32_t marker;
	uint32_t id;
	uint32_t size;
} IxNpeDlImageMgrImageHeader;

static int
npe_findimage(struct ixpnpe_softc *sc,
    const uint32_t *imageLibrary, uint32_t imageId,
    const uint32_t **imagePtr, uint32_t *imageSize)
{
	const IxNpeDlImageMgrImageHeader *image;
	uint32_t offset = 0;

	while (imageLibrary[offset] == NPE_IMAGE_MARKER) {
		image = (const IxNpeDlImageMgrImageHeader *)
		    &imageLibrary[offset];
		offset += sizeof(IxNpeDlImageMgrImageHeader)/sizeof(uint32_t);
		
		DPRINTF(sc->sc_dev, "%s: off %u mark 0x%x id 0x%x size %u\n",
		    __func__, offset, image->marker, image->id, image->size);
		if (image->id == imageId) {
			*imagePtr = imageLibrary + offset;
			*imageSize = image->size;
			return 0;
		}
		/* 2 consecutive NPE_IMAGE_MARKER's indicates end of library */
		if (image->id == NPE_IMAGE_MARKER) {
			DPRINTF(sc->sc_dev, "imageId 0x%08x not found in "
			    "image library header\n", imageId);
			/* reached end of library, image not found */
			return ESRCH;
		}
		offset += image->size;
	}
	return ESRCH;
}

static int
ixpnpe_load_firmware(struct ixpnpe_softc *sc, const char *imageName,
    uint32_t imageId)
{
	static const char *devname[4] =
	     { "IXP425", "IXP435/IXP465", "DeviceID#2", "DeviceID#3" };
	uint32_t imageSize;
	const uint32_t *imageCodePtr;
	const struct firmware *fw;
	int error;

	DPRINTF(sc->sc_dev, "load %s, imageId 0x%08x\n", imageName, imageId);

#if 0
	IxFeatureCtrlDeviceId devid = IX_NPEDL_DEVICEID_FROM_IMAGEID_GET(imageId);
	/*
	 * Checking if image being loaded is meant for device that is running.
	 * Image is forward compatible. i.e Image built for IXP42X should run
	 * on IXP46X but not vice versa.
	 */
	if (devid > (ixFeatureCtrlDeviceRead() & IX_FEATURE_CTRL_DEVICE_TYPE_MASK))
	    return EINVAL;
#endif
	error = ixpnpe_stopandreset(sc);		/* stop and reset the NPE */
	if (error != 0)
		return error;

	fw = firmware_get(imageName);
	if (fw == NULL)
		return ENOENT;

	/* Locate desired image in files w/ combined images */
	error = npe_findimage(sc, fw->data, imageId, &imageCodePtr, &imageSize);
	if (error != 0)
		goto done;

	device_printf(sc->sc_dev,
	    "load fw image %s.NPE-%c Func 0x%x Rev %u.%u\n",
	    devname[NPEIMAGE_DEVID(imageId)], 'A' + NPEIMAGE_NPEID(imageId),
	    NPEIMAGE_FUNCID(imageId), NPEIMAGE_MAJOR(imageId),
	    NPEIMAGE_MINOR(imageId));

	/*
	 * If download was successful, store image Id in list of
	 * currently loaded images. If a critical error occurred
	 * during download, record that the NPE has an invalid image
	 */
	mtx_lock(&sc->sc_mtx);
	error = npe_load_image(sc, imageCodePtr, 1 /*VERIFY*/);
	if (error == 0) {
		sc->validImage = 1;
		error = ixpnpe_start_locked(sc);
	} else {
		sc->validImage = 0;
	}
	sc->functionalityId = IX_NPEDL_FUNCTIONID_FROM_IMAGEID_GET(imageId);
	mtx_unlock(&sc->sc_mtx);
done:
	firmware_put(fw, FIRMWARE_UNLOAD);
	DPRINTF(sc->sc_dev, "%s: error %d\n", __func__, error);
	return error;
}

static int
override_imageid(device_t dev, const char *resname, uint32_t *val)
{
	int unit = device_get_unit(dev);
	int resval;

	if (resource_int_value("npe", unit, resname, &resval) != 0)
		return 0;
	/* XXX validate */
	if (bootverbose)
		device_printf(dev, "using npe.%d.%s=0x%x override\n",
		    unit, resname, resval);
	*val = resval;
	return 1;
}

int
ixpnpe_init(struct ixpnpe_softc *sc)
{
	static const uint32_t npeconfig[NPE_MAX] = {
		[NPE_A] = IXP425_NPE_A_IMAGEID,
		[NPE_B] = IXP425_NPE_B_IMAGEID,
		[NPE_C] = IXP425_NPE_C_IMAGEID,
	};
	uint32_t imageid, msg[2];
	int error;

	if (sc->started)
		return 0;
	/*
	 * Load NPE firmware and start it running.  We assume
	 * that minor version bumps remain compatible so probe
	 * the firmware image starting with the expected version
	 * and then bump the minor version up to the max.
	 */
	if (!override_imageid(sc->sc_dev, "imageid", &imageid))
		imageid = npeconfig[sc->sc_npeid];
	for (;;) {
		error = ixpnpe_load_firmware(sc, "npe_fw", imageid);
		if (error == 0)
			break;
		/*
		 * ESRCH is returned when the requested image
		 * is not present
		 */
		if (error != ESRCH) {
			device_printf(sc->sc_dev,
			    "cannot init NPE (error %d)\n", error);
			return error;
		}
		/* bump the minor version up to the max possible */
		if (NPEIMAGE_MINOR(imageid) == 0xff) {
			device_printf(sc->sc_dev, "cannot locate firmware "
			    "(imageid 0x%08x)\n", imageid);
			return error;
		}
		imageid++;
	}
	/* NB: firmware should respond with a status msg */
	if (ixpnpe_recvmsg_sync(sc, msg) != 0) {
		device_printf(sc->sc_dev,
		    "firmware did not respond as expected\n");
		return EIO;
	}
	return 0;
}

int
ixpnpe_getfunctionality(struct ixpnpe_softc *sc)
{
	return (sc->validImage ? sc->functionalityId : 0);
}

static int
npe_checkbits(struct ixpnpe_softc *sc, uint32_t reg, uint32_t expectedBitsSet)
{
	uint32_t val;

	val = npe_reg_read(sc, reg);
	DPRINTFn(5, sc->sc_dev, "%s(0x%x, 0x%x) => 0x%x (%u)\n",
	    __func__, reg, expectedBitsSet, val,
	    (val & expectedBitsSet) == expectedBitsSet);
	return ((val & expectedBitsSet) == expectedBitsSet);
}

static int
npe_isstopped(struct ixpnpe_softc *sc)
{
	return npe_checkbits(sc,
	    IX_NPEDL_REG_OFFSET_EXCTL, IX_NPEDL_EXCTL_STATUS_STOP);
}

static int
npe_load_ins(struct ixpnpe_softc *sc,
    const IxNpeDlNpeMgrCodeBlock *bp, int verify)
{
	uint32_t npeMemAddress;
	int i, blockSize;

	npeMemAddress = bp->npeMemAddress;
	blockSize = bp->size;		/* NB: instruction/data count */
	if (npeMemAddress + blockSize > sc->insMemSize) {
		device_printf(sc->sc_dev,
		    "Block size %u too big for NPE memory\n", blockSize);
		return EINVAL;	/* XXX */
	}
	for (i = 0; i < blockSize; i++, npeMemAddress++) {
		if (npe_ins_write(sc, npeMemAddress, bp->data[i], verify) != 0) {
			device_printf(sc->sc_dev,
			    "NPE instruction write failed");
			return EIO;
		}
	}
	return 0;
}

static int
npe_load_data(struct ixpnpe_softc *sc,
    const IxNpeDlNpeMgrCodeBlock *bp, int verify)
{
	uint32_t npeMemAddress;
	int i, blockSize;

	npeMemAddress = bp->npeMemAddress;
	blockSize = bp->size;		/* NB: instruction/data count */
	if (npeMemAddress + blockSize > sc->dataMemSize) {
		device_printf(sc->sc_dev,
		    "Block size %u too big for NPE memory\n", blockSize);
		return EINVAL;
	}
	for (i = 0; i < blockSize; i++, npeMemAddress++) {
		if (npe_data_write(sc, npeMemAddress, bp->data[i], verify) != 0) {
			device_printf(sc->sc_dev, "NPE data write failed\n");
			return EIO;
		}
	}
	return 0;
}

static int
npe_load_stateinfo(struct ixpnpe_softc *sc,
    const IxNpeDlNpeMgrStateInfoBlock *bp, int verify)
{
	int i, nentries, error;

	npe_cpu_step_save(sc);

	/* for each state-info context register entry in block */
	nentries = bp->size / IX_NPEDL_STATE_INFO_ENTRY_SIZE;
	error = 0;
	for (i = 0; i < nentries; i++) {
		/* each state-info entry is 2 words (address, value) */
		uint32_t regVal = bp->ctxtRegEntry[i].value;
		uint32_t addrInfo = bp->ctxtRegEntry[i].addressInfo;

		uint32_t reg = (addrInfo & IX_NPEDL_MASK_STATE_ADDR_CTXT_REG);
		uint32_t cNum = (addrInfo & IX_NPEDL_MASK_STATE_ADDR_CTXT_NUM) >>
		    IX_NPEDL_OFFSET_STATE_ADDR_CTXT_NUM;
		
		/* error-check Context Register No. and Context Number values */
		if (!(0 <= reg && reg < IX_NPEDL_CTXT_REG_MAX)) {
			device_printf(sc->sc_dev,
			    "invalid Context Register %u\n", reg);
			error = EINVAL;
			break;
		}
		if (!(0 <= cNum && cNum < IX_NPEDL_CTXT_NUM_MAX)) {
			device_printf(sc->sc_dev,
			    "invalid Context Number %u\n", cNum);
			error = EINVAL;
			break;
		}
		/* NOTE that there is no STEVT register for Context 0 */
		if (cNum == 0 && reg == IX_NPEDL_CTXT_REG_STEVT) {
			device_printf(sc->sc_dev,
			    "no STEVT for Context 0\n");
			error = EINVAL;
			break;
		}

		if (npe_ctx_reg_write(sc, cNum, reg, regVal, verify) != 0) {
			device_printf(sc->sc_dev,
			    "write of state-info to NPE failed\n");
			error = EIO;
			break;
		}
	}

	npe_cpu_step_restore(sc);
	return error;
}

static int
npe_load_image(struct ixpnpe_softc *sc,
    const uint32_t *imageCodePtr, int verify)
{
#define	EOM(marker)	((marker) == IX_NPEDL_END_OF_DOWNLOAD_MAP)
	const IxNpeDlNpeMgrDownloadMap *downloadMap;
	int i, error;

	if (!npe_isstopped(sc)) {		/* verify NPE is stopped */
		device_printf(sc->sc_dev,
		    "cannot load image, NPE not stopped\n");
		return EIO;
	}

	/*
	 * Read Download Map, checking each block type and calling
	 * appropriate function to perform download
	 */
	error = 0;
	downloadMap = (const IxNpeDlNpeMgrDownloadMap *) imageCodePtr;
	for (i = 0; !EOM(downloadMap->entry[i].eodmMarker); i++) {
		/* calculate pointer to block to be downloaded */
		const uint32_t *bp = imageCodePtr +
		    downloadMap->entry[i].block.offset;
		switch (downloadMap->entry[i].block.type) {
		case IX_NPEDL_BLOCK_TYPE_INSTRUCTION:
			error = npe_load_ins(sc,
			    (const IxNpeDlNpeMgrCodeBlock *) bp, verify);
			DPRINTF(sc->sc_dev, "%s: inst, error %d\n",
			    __func__, error);
			break;
		case IX_NPEDL_BLOCK_TYPE_DATA:
			error = npe_load_data(sc,
			    (const IxNpeDlNpeMgrCodeBlock *) bp, verify);
			DPRINTF(sc->sc_dev, "%s: data, error %d\n",
			    __func__, error);
			break;
		case IX_NPEDL_BLOCK_TYPE_STATE:
		    error = npe_load_stateinfo(sc,
			(const IxNpeDlNpeMgrStateInfoBlock *) bp, verify);
			DPRINTF(sc->sc_dev, "%s: state, error %d\n",
			    __func__, error);
			break;
		default:
			device_printf(sc->sc_dev,
			    "unknown block type 0x%x in download map\n",
			    downloadMap->entry[i].block.type);
			error = EIO;		/* XXX */
			break;
		}
		if (error != 0)
			break;
	}
	return error;
#undef EOM
}

/* contains Reset values for Context Store Registers  */
static const struct {
	uint32_t regAddr;
	uint32_t regResetVal;
} ixNpeDlEcsRegResetValues[] = {
	{ IX_NPEDL_ECS_BG_CTXT_REG_0,    IX_NPEDL_ECS_BG_CTXT_REG_0_RESET },
	{ IX_NPEDL_ECS_BG_CTXT_REG_1,    IX_NPEDL_ECS_BG_CTXT_REG_1_RESET },
	{ IX_NPEDL_ECS_BG_CTXT_REG_2,    IX_NPEDL_ECS_BG_CTXT_REG_2_RESET },
	{ IX_NPEDL_ECS_PRI_1_CTXT_REG_0, IX_NPEDL_ECS_PRI_1_CTXT_REG_0_RESET },
	{ IX_NPEDL_ECS_PRI_1_CTXT_REG_1, IX_NPEDL_ECS_PRI_1_CTXT_REG_1_RESET },
	{ IX_NPEDL_ECS_PRI_1_CTXT_REG_2, IX_NPEDL_ECS_PRI_1_CTXT_REG_2_RESET },
	{ IX_NPEDL_ECS_PRI_2_CTXT_REG_0, IX_NPEDL_ECS_PRI_2_CTXT_REG_0_RESET },
	{ IX_NPEDL_ECS_PRI_2_CTXT_REG_1, IX_NPEDL_ECS_PRI_2_CTXT_REG_1_RESET },
	{ IX_NPEDL_ECS_PRI_2_CTXT_REG_2, IX_NPEDL_ECS_PRI_2_CTXT_REG_2_RESET },
	{ IX_NPEDL_ECS_DBG_CTXT_REG_0,   IX_NPEDL_ECS_DBG_CTXT_REG_0_RESET },
	{ IX_NPEDL_ECS_DBG_CTXT_REG_1,   IX_NPEDL_ECS_DBG_CTXT_REG_1_RESET },
	{ IX_NPEDL_ECS_DBG_CTXT_REG_2,   IX_NPEDL_ECS_DBG_CTXT_REG_2_RESET },
	{ IX_NPEDL_ECS_INSTRUCT_REG,     IX_NPEDL_ECS_INSTRUCT_REG_RESET }
};

/* contains Reset values for Context Store Registers  */
static const uint32_t ixNpeDlCtxtRegResetValues[] = {
	IX_NPEDL_CTXT_REG_RESET_STEVT,
	IX_NPEDL_CTXT_REG_RESET_STARTPC,
	IX_NPEDL_CTXT_REG_RESET_REGMAP,
	IX_NPEDL_CTXT_REG_RESET_CINDEX,
};

#define	IX_NPEDL_PARITY_BIT_MASK	0x3F00FFFF
#define	IX_NPEDL_CONFIG_CTRL_REG_MASK	0x3F3FFFFF

#if 0
/*
 * Reset the NPE and its coprocessor using the
 * fuse bits in the feature control register.
 */
static void
npe_reset(int npeid)
{
	uint32_t mask = EXP_FCTRL_NPEA << npeid;
	uint32_t v;

	v = ixp4xx_read_feature_bits();
	ixp4xx_write_feature_bits(v &~ mask);
	/* un-fuse and un-reset the NPE & coprocessor */
	ixp4xx_write_feature_bits(v | mask);
}
#endif

static int
npe_cpu_reset(struct ixpnpe_softc *sc)
{
#define	N(a)	(sizeof(a) / sizeof(a[0]))
	uint32_t ctxtReg; /* identifies Context Store reg (0-3) */
	uint32_t regAddr;
	uint32_t regVal;
	uint32_t ixNpeConfigCtrlRegVal;
	int i, error = 0;
	
	/* pre-store the NPE Config Control Register Value */
	ixNpeConfigCtrlRegVal = npe_reg_read(sc, IX_NPEDL_REG_OFFSET_CTL);
	ixNpeConfigCtrlRegVal |= 0x3F000000;

	/* disable the parity interrupt */
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_CTL,
	    (ixNpeConfigCtrlRegVal & IX_NPEDL_PARITY_BIT_MASK));
	DPRINTFn(2, sc->sc_dev, "%s: dis parity int, CTL => 0x%x\n",
	    __func__, ixNpeConfigCtrlRegVal & IX_NPEDL_PARITY_BIT_MASK);

	npe_cpu_step_save(sc);

	/*
	 * Clear the FIFOs.
	 */
	while (npe_checkbits(sc,
	      IX_NPEDL_REG_OFFSET_WFIFO, IX_NPEDL_MASK_WFIFO_VALID)) {
		/* read from the Watch-point FIFO until empty */
		(void) npe_reg_read(sc, IX_NPEDL_REG_OFFSET_WFIFO);
	}

	while (npe_checkbits(sc,
	      IX_NPEDL_REG_OFFSET_STAT, IX_NPEDL_MASK_STAT_OFNE)) {
		/* read from the outFIFO until empty */
		(void) npe_reg_read(sc, IX_NPEDL_REG_OFFSET_FIFO);
	}
	
	while (npe_checkbits(sc,
	      IX_NPEDL_REG_OFFSET_STAT, IX_NPEDL_MASK_STAT_IFNE)) {
		/*
		 * Step execution of the NPE instruction to read inFIFO using
		 * the Debug Executing Context stack.
		 */
		error = npe_cpu_step(sc, IX_NPEDL_INSTR_RD_FIFO, 0, 0);
		if (error != 0) {
			DPRINTF(sc->sc_dev, "%s: cannot step (1), error %u\n",
			    __func__, error);
			npe_cpu_step_restore(sc);
			return error;
		}
	}
	
	/*
	 * Reset the mailbox reg
	 */
	/* ...from XScale side */
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_MBST, IX_NPEDL_REG_RESET_MBST);
	/* ...from NPE side */
	error = npe_cpu_step(sc, IX_NPEDL_INSTR_RESET_MBOX, 0, 0);
	if (error != 0) {
		DPRINTF(sc->sc_dev, "%s: cannot step (2), error %u\n",
		    __func__, error);
		npe_cpu_step_restore(sc);
		return error;
	}

	/*
	 * Reset the physical registers in the NPE register file:
	 * Note: no need to save/restore REGMAP for Context 0 here
	 * since all Context Store regs are reset in subsequent code.
	 */
	for (regAddr = 0;
	     regAddr < IX_NPEDL_TOTAL_NUM_PHYS_REG && error == 0;
	     regAddr++) {
		/* for each physical register in the NPE reg file, write 0 : */
		error = npe_physical_reg_write(sc, regAddr, 0, TRUE);
		if (error != 0) {
			DPRINTF(sc->sc_dev, "%s: cannot write phy reg,"
			    "error %u\n", __func__, error);
			npe_cpu_step_restore(sc);
			return error;		/* abort reset */
		}
	}

	/*
	 * Reset the context store:
	 */
	for (i = IX_NPEDL_CTXT_NUM_MIN; i <= IX_NPEDL_CTXT_NUM_MAX; i++) {	
		/* set each context's Context Store registers to reset values */
		for (ctxtReg = 0; ctxtReg < IX_NPEDL_CTXT_REG_MAX; ctxtReg++) {
			/* NOTE that there is no STEVT register for Context 0 */
			if (i == 0 && ctxtReg == IX_NPEDL_CTXT_REG_STEVT)
				continue;
			regVal = ixNpeDlCtxtRegResetValues[ctxtReg];
			error = npe_ctx_reg_write(sc, i, ctxtReg,
			    regVal, TRUE);
			if (error != 0) {
				DPRINTF(sc->sc_dev, "%s: cannot write ctx reg,"
				    "error %u\n", __func__, error);
				npe_cpu_step_restore(sc);
				return error;	 /* abort reset */
			}
		}
	}

	npe_cpu_step_restore(sc);

	/* write Reset values to Execution Context Stack registers */
	for (i = 0; i < N(ixNpeDlEcsRegResetValues); i++)
		npe_ecs_reg_write(sc,
		    ixNpeDlEcsRegResetValues[i].regAddr,
		    ixNpeDlEcsRegResetValues[i].regResetVal);

	/* clear the profile counter */
	npe_issue_cmd(sc, IX_NPEDL_EXCTL_CMD_CLR_PROFILE_CNT);
	
	/* clear registers EXCT, AP0, AP1, AP2 and AP3 */
	for (regAddr = IX_NPEDL_REG_OFFSET_EXCT;
	     regAddr <= IX_NPEDL_REG_OFFSET_AP3;
	     regAddr += sizeof(uint32_t))
		npe_reg_write(sc, regAddr, 0);

	/* Reset the Watch-count register */
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_WC, 0);
#if 0
	/*
	 * WR IXA00055043 - Remove IMEM Parity Introduced by NPE Reset Operation
	 * XXX Removed because it breaks IXP435 operation; e.g. on Gateworks
	 * XXX 2358 boards reseting NPE-A after NPE-C is running causes both
	 * XXX npe's to stop working
	 */
	npe_reset(sc->sc_npeid);
#endif
	/*
	 * Call NpeMgr function to stop the NPE again after the Feature Control
	 * has unfused and Un-Reset the NPE and its associated Coprocessors.
	 */
	error = npe_cpu_stop(sc);

	/* restore NPE configuration bus Control Register - Parity Settings  */
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_CTL,
	    (ixNpeConfigCtrlRegVal & IX_NPEDL_CONFIG_CTRL_REG_MASK));
	DPRINTFn(2, sc->sc_dev, "%s: restore CTL => 0x%x\n",
	    __func__, npe_reg_read(sc, IX_NPEDL_REG_OFFSET_CTL));

	return error;
#undef N
}

static int
npe_cpu_start(struct ixpnpe_softc *sc)
{
	uint32_t ecsRegVal;

	/*
	 * Ensure only Background Context Stack Level is Active by turning off
	 * the Active bit in each of the other Executing Context Stack levels.
	 */
	ecsRegVal = npe_ecs_reg_read(sc, IX_NPEDL_ECS_PRI_1_CTXT_REG_0);
	ecsRegVal &= ~IX_NPEDL_MASK_ECS_REG_0_ACTIVE;
	npe_ecs_reg_write(sc, IX_NPEDL_ECS_PRI_1_CTXT_REG_0, ecsRegVal);

	ecsRegVal = npe_ecs_reg_read(sc, IX_NPEDL_ECS_PRI_2_CTXT_REG_0);
	ecsRegVal &= ~IX_NPEDL_MASK_ECS_REG_0_ACTIVE;
	npe_ecs_reg_write(sc, IX_NPEDL_ECS_PRI_2_CTXT_REG_0, ecsRegVal);

	ecsRegVal = npe_ecs_reg_read(sc, IX_NPEDL_ECS_DBG_CTXT_REG_0);
	ecsRegVal &= ~IX_NPEDL_MASK_ECS_REG_0_ACTIVE;
	npe_ecs_reg_write(sc, IX_NPEDL_ECS_DBG_CTXT_REG_0, ecsRegVal);
	
	/* clear the pipeline */
	npe_issue_cmd(sc, IX_NPEDL_EXCTL_CMD_NPE_CLR_PIPE);
	
	/* start NPE execution by issuing cmd through EXCTL register on NPE */
	npe_issue_cmd(sc, IX_NPEDL_EXCTL_CMD_NPE_START);

	/*
	 * Check execution status of NPE to verify operation was successful.
	 */
	return npe_checkbits(sc,
	    IX_NPEDL_REG_OFFSET_EXCTL, IX_NPEDL_EXCTL_STATUS_RUN) ? 0 : EIO;
}

static int
npe_cpu_stop(struct ixpnpe_softc *sc)
{
	/* stop NPE execution by issuing cmd through EXCTL register on NPE */
	npe_issue_cmd(sc, IX_NPEDL_EXCTL_CMD_NPE_STOP);

	/* verify that NPE Stop was successful */
	return npe_checkbits(sc,
	    IX_NPEDL_REG_OFFSET_EXCTL, IX_NPEDL_EXCTL_STATUS_STOP) ? 0 : EIO;
}

#define IX_NPEDL_REG_SIZE_BYTE            8
#define IX_NPEDL_REG_SIZE_SHORT           16
#define IX_NPEDL_REG_SIZE_WORD            32

/*
 * Introduce extra read cycles after issuing read command to NPE
 * so that we read the register after the NPE has updated it
 * This is to overcome race condition between XScale and NPE
 */
#define IX_NPEDL_DELAY_READ_CYCLES        2
/*
 * To mask top three MSBs of 32bit word to download into NPE IMEM
 */
#define IX_NPEDL_MASK_UNUSED_IMEM_BITS    0x1FFFFFFF;

static void
npe_cmd_issue_write(struct ixpnpe_softc *sc,
    uint32_t cmd, uint32_t addr, uint32_t data)
{
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXDATA, data);
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXAD, addr);
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXCTL, cmd);
}

static uint32_t
npe_cmd_issue_read(struct ixpnpe_softc *sc, uint32_t cmd, uint32_t addr)
{
	uint32_t data;
	int i;

	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXAD, addr);
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXCTL, cmd);
	for (i = 0; i <= IX_NPEDL_DELAY_READ_CYCLES; i++)
		data = npe_reg_read(sc, IX_NPEDL_REG_OFFSET_EXDATA);
	return data;
}

static int
npe_ins_write(struct ixpnpe_softc *sc, uint32_t addr, uint32_t data, int verify)
{
	DPRINTFn(4, sc->sc_dev, "%s(0x%x, 0x%x)\n", __func__, addr, data);
	npe_cmd_issue_write(sc, IX_NPEDL_EXCTL_CMD_WR_INS_MEM, addr, data);
	if (verify) {
		uint32_t rdata;

		/*
		 * Write invalid data to this reg, so we can see if we're
		 * reading the EXDATA register too early.
		 */
		npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXDATA, ~data);

		/*
		 * Disabled since top 3 MSB are not used for Azusa
		 * hardware Refer WR:IXA00053900
		 */
		data &= IX_NPEDL_MASK_UNUSED_IMEM_BITS;

		rdata = npe_cmd_issue_read(sc, IX_NPEDL_EXCTL_CMD_RD_INS_MEM,
		    addr);
		rdata &= IX_NPEDL_MASK_UNUSED_IMEM_BITS;

		if (data != rdata)
			return EIO;
	}
	return 0;
}

static int
npe_data_write(struct ixpnpe_softc *sc, uint32_t addr, uint32_t data, int verify)
{
	DPRINTFn(4, sc->sc_dev, "%s(0x%x, 0x%x)\n", __func__, addr, data);
	npe_cmd_issue_write(sc, IX_NPEDL_EXCTL_CMD_WR_DATA_MEM, addr, data);
	if (verify) {
		/*
		 * Write invalid data to this reg, so we can see if we're
		 * reading the EXDATA register too early.
		 */
		npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXDATA, ~data);
		if (data != npe_cmd_issue_read(sc, IX_NPEDL_EXCTL_CMD_RD_DATA_MEM, addr))
			return EIO;
	}
	return 0;
}

static void
npe_ecs_reg_write(struct ixpnpe_softc *sc, uint32_t reg, uint32_t data)
{
	npe_cmd_issue_write(sc, IX_NPEDL_EXCTL_CMD_WR_ECS_REG, reg, data);
}

static uint32_t
npe_ecs_reg_read(struct ixpnpe_softc *sc, uint32_t reg)
{
	return npe_cmd_issue_read(sc, IX_NPEDL_EXCTL_CMD_RD_ECS_REG, reg);
}

static void
npe_issue_cmd(struct ixpnpe_softc *sc, uint32_t command)
{
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXCTL, command);
}

static void
npe_cpu_step_save(struct ixpnpe_softc *sc)
{
	/* turn off the halt bit by clearing Execution Count register. */
	/* save reg contents 1st and restore later */
	sc->savedExecCount = npe_reg_read(sc, IX_NPEDL_REG_OFFSET_EXCT);
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXCT, 0);

	/* ensure that IF and IE are on (temporarily), so that we don't end up
	 * stepping forever */
	sc->savedEcsDbgCtxtReg2 = npe_ecs_reg_read(sc,
	    IX_NPEDL_ECS_DBG_CTXT_REG_2);

	npe_ecs_reg_write(sc, IX_NPEDL_ECS_DBG_CTXT_REG_2,
	    (sc->savedEcsDbgCtxtReg2 | IX_NPEDL_MASK_ECS_DBG_REG_2_IF |
	     IX_NPEDL_MASK_ECS_DBG_REG_2_IE));
}

static int
npe_cpu_step(struct ixpnpe_softc *sc, uint32_t npeInstruction,
    uint32_t ctxtNum, uint32_t ldur)
{
#define	IX_NPE_DL_MAX_NUM_OF_RETRIES	1000000
	uint32_t ecsDbgRegVal;
	uint32_t oldWatchcount, newWatchcount;
	int tries;

	/* set the Active bit, and the LDUR, in the debug level */
	ecsDbgRegVal = IX_NPEDL_MASK_ECS_REG_0_ACTIVE |
	    (ldur << IX_NPEDL_OFFSET_ECS_REG_0_LDUR);

	npe_ecs_reg_write(sc, IX_NPEDL_ECS_DBG_CTXT_REG_0, ecsDbgRegVal);

	/*
	 * Set CCTXT at ECS DEBUG L3 to specify in which context to execute the
	 * instruction, and set SELCTXT at ECS DEBUG Level to specify which
	 * context store to access.
	 * Debug ECS Level Reg 1 has form  0x000n000n, where n = context number
	 */
	ecsDbgRegVal = (ctxtNum << IX_NPEDL_OFFSET_ECS_REG_1_CCTXT) |
	    (ctxtNum << IX_NPEDL_OFFSET_ECS_REG_1_SELCTXT);

	npe_ecs_reg_write(sc, IX_NPEDL_ECS_DBG_CTXT_REG_1, ecsDbgRegVal);

	/* clear the pipeline */
	npe_issue_cmd(sc, IX_NPEDL_EXCTL_CMD_NPE_CLR_PIPE);

	/* load NPE instruction into the instruction register */
	npe_ecs_reg_write(sc, IX_NPEDL_ECS_INSTRUCT_REG, npeInstruction);

	/* need this value later to wait for completion of NPE execution step */
	oldWatchcount = npe_reg_read(sc, IX_NPEDL_REG_OFFSET_WC);

	/* issue a Step One command via the Execution Control register */
	npe_issue_cmd(sc, IX_NPEDL_EXCTL_CMD_NPE_STEP);

	/*
	 * Force the XScale to wait until the NPE has finished execution step
	 * NOTE that this delay will be very small, just long enough to allow a
	 * single NPE instruction to complete execution; if instruction
	 * execution is not completed before timeout retries, exit the while
	 * loop.
	 */
	newWatchcount = npe_reg_read(sc, IX_NPEDL_REG_OFFSET_WC);
	for (tries = 0; tries < IX_NPE_DL_MAX_NUM_OF_RETRIES &&
	    newWatchcount == oldWatchcount; tries++) {
		/* Watch Count register incr's when NPE completes an inst */
		newWatchcount = npe_reg_read(sc, IX_NPEDL_REG_OFFSET_WC);
	}
	return (tries < IX_NPE_DL_MAX_NUM_OF_RETRIES) ? 0 : EIO;
#undef IX_NPE_DL_MAX_NUM_OF_RETRIES
}

static void
npe_cpu_step_restore(struct ixpnpe_softc *sc)
{
	/* clear active bit in debug level */
	npe_ecs_reg_write(sc, IX_NPEDL_ECS_DBG_CTXT_REG_0, 0);

	/* clear the pipeline */
	npe_issue_cmd(sc, IX_NPEDL_EXCTL_CMD_NPE_CLR_PIPE);

	/* restore Execution Count register contents. */
	npe_reg_write(sc, IX_NPEDL_REG_OFFSET_EXCT, sc->savedExecCount);

	/* restore IF and IE bits to original values */
	npe_ecs_reg_write(sc, IX_NPEDL_ECS_DBG_CTXT_REG_2, sc->savedEcsDbgCtxtReg2);
}

static int
npe_logical_reg_read(struct ixpnpe_softc *sc,
    uint32_t regAddr, uint32_t regSize,
    uint32_t ctxtNum, uint32_t *regVal)
{
	uint32_t npeInstruction, mask;
	int error;

	switch (regSize) {
	case IX_NPEDL_REG_SIZE_BYTE:
		npeInstruction = IX_NPEDL_INSTR_RD_REG_BYTE;
		mask = 0xff;
		break;
	case IX_NPEDL_REG_SIZE_SHORT:
		npeInstruction = IX_NPEDL_INSTR_RD_REG_SHORT;
		mask = 0xffff;
		break;
	case IX_NPEDL_REG_SIZE_WORD:
		npeInstruction = IX_NPEDL_INSTR_RD_REG_WORD;
		mask = 0xffffffff;
		break;
	default:
		return EINVAL;
	}

	/* make regAddr be the SRC and DEST operands (e.g. movX d0, d0) */
	npeInstruction |= (regAddr << IX_NPEDL_OFFSET_INSTR_SRC) |
	    (regAddr << IX_NPEDL_OFFSET_INSTR_DEST);

	/* step execution of NPE inst using Debug Executing Context stack */
	error = npe_cpu_step(sc, npeInstruction, ctxtNum,
	    IX_NPEDL_RD_INSTR_LDUR);
	if (error != 0) {
		DPRINTF(sc->sc_dev, "%s(0x%x, %u, %u), cannot step, error %d\n",
		    __func__, regAddr, regSize, ctxtNum, error);
		return error;
	}
	/* read value of register from Execution Data register */
	*regVal = npe_reg_read(sc, IX_NPEDL_REG_OFFSET_EXDATA);

	/* align value from left to right */
	*regVal = (*regVal >> (IX_NPEDL_REG_SIZE_WORD - regSize)) & mask;

	return 0;
}

static int
npe_logical_reg_write(struct ixpnpe_softc *sc, uint32_t regAddr, uint32_t regVal,
    uint32_t regSize, uint32_t ctxtNum, int verify)
{
	int error;

	DPRINTFn(4, sc->sc_dev, "%s(0x%x, 0x%x, %u, %u)\n",
	    __func__, regAddr, regVal, regSize, ctxtNum);
	if (regSize == IX_NPEDL_REG_SIZE_WORD) {
		/*
		 * NPE register addressing is left-to-right: e.g. |d0|d1|d2|d3|
		 * Write upper half-word (short) to |d0|d1|
		 */
		error = npe_logical_reg_write(sc, regAddr,
			     regVal >> IX_NPEDL_REG_SIZE_SHORT,
			     IX_NPEDL_REG_SIZE_SHORT, ctxtNum, verify);
		if (error != 0)
		    return error;

		/* Write lower half-word (short) to |d2|d3| */
		error = npe_logical_reg_write(sc,
			     regAddr + sizeof(uint16_t),
			     regVal & 0xffff,
			     IX_NPEDL_REG_SIZE_SHORT, ctxtNum, verify);
	} else {
		uint32_t npeInstruction;

		switch (regSize) {
		case IX_NPEDL_REG_SIZE_BYTE:
			npeInstruction = IX_NPEDL_INSTR_WR_REG_BYTE;
			regVal &= 0xff;
			break;
		case IX_NPEDL_REG_SIZE_SHORT:
			npeInstruction = IX_NPEDL_INSTR_WR_REG_SHORT;
			regVal &= 0xffff;
			break;
		default:
			return EINVAL;
		}
		/* fill dest operand field of inst with dest reg addr */
		npeInstruction |= (regAddr << IX_NPEDL_OFFSET_INSTR_DEST);

		/* fill src operand field of inst with least-sig 5 bits of val*/
		npeInstruction |=
		    ((regVal & IX_NPEDL_MASK_IMMED_INSTR_SRC_DATA) <<
		     IX_NPEDL_OFFSET_INSTR_SRC);

		/* fill coprocessor field of inst with most-sig 11 bits of val*/
		npeInstruction |=
		    ((regVal & IX_NPEDL_MASK_IMMED_INSTR_COPROC_DATA) <<
		     IX_NPEDL_DISPLACE_IMMED_INSTR_COPROC_DATA);

		/* step execution of NPE instruction using Debug ECS */
		error = npe_cpu_step(sc, npeInstruction,
		    ctxtNum, IX_NPEDL_WR_INSTR_LDUR);
	}
	if (error != 0) {
		DPRINTF(sc->sc_dev, "%s(0x%x, 0x%x, %u, %u), error %u "
		    "writing reg\n", __func__, regAddr, regVal, regSize,
		    ctxtNum, error);
		return error;
	}
	if (verify) {
		uint32_t retRegVal;

		error = npe_logical_reg_read(sc, regAddr, regSize, ctxtNum,
		    &retRegVal);
		if (error == 0 && regVal != retRegVal)
			error = EIO;	/* XXX ambiguous */
	}
	return error;
}

/*
 * There are 32 physical registers used in an NPE.  These are
 * treated as 16 pairs of 32-bit registers.  To write one of the pair,
 * write the pair number (0-16) to the REGMAP for Context 0.  Then write
 * the value to register  0 or 4 in the regfile, depending on which
 * register of the pair is to be written
 */
static int
npe_physical_reg_write(struct ixpnpe_softc *sc,
    uint32_t regAddr, uint32_t regValue, int verify)
{
	int error;

	/*
	 * Set REGMAP for context 0 to (regAddr >> 1) to choose which pair
	 * (0-16) of physical registers to write .
	 */
	error = npe_logical_reg_write(sc, IX_NPEDL_CTXT_REG_ADDR_REGMAP,
		   (regAddr >> IX_NPEDL_OFFSET_PHYS_REG_ADDR_REGMAP),
		   IX_NPEDL_REG_SIZE_SHORT, 0, verify);
	if (error == 0) {
	    /* regAddr = 0 or 4  */
	    regAddr = (regAddr & IX_NPEDL_MASK_PHYS_REG_ADDR_LOGICAL_ADDR) *
		sizeof(uint32_t);
	    error = npe_logical_reg_write(sc, regAddr, regValue,
		IX_NPEDL_REG_SIZE_WORD, 0, verify);
	}
	return error;
}

static int
npe_ctx_reg_write(struct ixpnpe_softc *sc, uint32_t ctxtNum,
    uint32_t ctxtReg, uint32_t ctxtRegVal, int verify)
{
	DPRINTFn(4, sc->sc_dev, "%s(%u, %u, %u)\n",
	    __func__, ctxtNum, ctxtReg, ctxtRegVal);
	/*
	 * Context 0 has no STARTPC. Instead, this value is used to set
	 * NextPC for Background ECS, to set where NPE starts executing code
	 */
	if (ctxtNum == 0 && ctxtReg == IX_NPEDL_CTXT_REG_STARTPC) {
		/* read BG_CTXT_REG_0, update NEXTPC bits, & write back to reg*/
		uint32_t v = npe_ecs_reg_read(sc, IX_NPEDL_ECS_BG_CTXT_REG_0);
		v &= ~IX_NPEDL_MASK_ECS_REG_0_NEXTPC;
		v |= (ctxtRegVal << IX_NPEDL_OFFSET_ECS_REG_0_NEXTPC) &
		    IX_NPEDL_MASK_ECS_REG_0_NEXTPC;

		npe_ecs_reg_write(sc, IX_NPEDL_ECS_BG_CTXT_REG_0, v);
		return 0;
	} else {
		static const struct {
			uint32_t regAddress;
			uint32_t regSize;
		} regAccInfo[IX_NPEDL_CTXT_REG_MAX] = {
			{ IX_NPEDL_CTXT_REG_ADDR_STEVT,
			  IX_NPEDL_REG_SIZE_BYTE },
			{ IX_NPEDL_CTXT_REG_ADDR_STARTPC,
			  IX_NPEDL_REG_SIZE_SHORT },
			{ IX_NPEDL_CTXT_REG_ADDR_REGMAP,
			  IX_NPEDL_REG_SIZE_SHORT },
			{ IX_NPEDL_CTXT_REG_ADDR_CINDEX,
			  IX_NPEDL_REG_SIZE_BYTE }
		};
		return npe_logical_reg_write(sc, regAccInfo[ctxtReg].regAddress,
			ctxtRegVal, regAccInfo[ctxtReg].regSize, ctxtNum, verify);
	}
}

/*
 * NPE Mailbox support.
 */
#define	IX_NPEMH_MAXTRIES	100000

static int
ofifo_wait(struct ixpnpe_softc *sc)
{
	int i;

	for (i = 0; i < IX_NPEMH_MAXTRIES; i++) {
		if (npe_reg_read(sc, IX_NPESTAT) & IX_NPESTAT_OFNE)
			return 1;
		DELAY(10);
	}
	device_printf(sc->sc_dev, "%s: timeout, last status 0x%x\n",
	    __func__, npe_reg_read(sc, IX_NPESTAT));
	return 0;
}

static int
getmsg(struct ixpnpe_softc *sc, uint32_t msg[2])
{
	mtx_assert(&sc->sc_mtx, MA_OWNED);

	if (!ofifo_wait(sc))
		return EAGAIN;
	msg[0] = npe_reg_read(sc, IX_NPEFIFO);
	DPRINTF(sc->sc_dev, "%s: msg0 0x%x\n", __func__, msg[0]);
	if (!ofifo_wait(sc))
		return EAGAIN;
	msg[1] = npe_reg_read(sc, IX_NPEFIFO);
	DPRINTF(sc->sc_dev, "%s: msg1 0x%x\n", __func__, msg[1]);
	return 0;
}

static void
ixpnpe_intr(void *arg)
{
	struct ixpnpe_softc *sc = arg;
	uint32_t status;

	mtx_lock(&sc->sc_mtx);
	status = npe_reg_read(sc, IX_NPESTAT);
	DPRINTF(sc->sc_dev, "%s: status 0x%x\n", __func__, status);
	if ((status & IX_NPESTAT_OFINT) == 0) {
		/* NB: should not happen */
		device_printf(sc->sc_dev, "%s: status 0x%x\n",
		    __func__, status);
		/* XXX must silence interrupt? */
		mtx_unlock(&sc->sc_mtx);
		return;
	}
	/*
	 * A message is waiting in the output FIFO, copy it so
	 * the interrupt will be silenced.
	 */
	if (getmsg(sc, sc->sc_msg) == 0)
		sc->sc_msgwaiting = 1;
	mtx_unlock(&sc->sc_mtx);
}

static int
ififo_wait(struct ixpnpe_softc *sc)
{
	int i;

	for (i = 0; i < IX_NPEMH_MAXTRIES; i++) {
		if (npe_reg_read(sc, IX_NPESTAT) & IX_NPESTAT_IFNF)
			return 1;
		DELAY(10);
	}
	device_printf(sc->sc_dev, "%s: timeout, last status 0x%x\n",
	    __func__, npe_reg_read(sc, IX_NPESTAT));
	return 0;
}

static int
putmsg(struct ixpnpe_softc *sc, const uint32_t msg[2])
{
	mtx_assert(&sc->sc_mtx, MA_OWNED);

	DPRINTF(sc->sc_dev, "%s: msg 0x%x:0x%x\n", __func__, msg[0], msg[1]);
	if (!ififo_wait(sc))
		return EIO;
	npe_reg_write(sc, IX_NPEFIFO, msg[0]);
	if (!ififo_wait(sc))
		return EIO;
	npe_reg_write(sc, IX_NPEFIFO, msg[1]);

	return 0;
}

/*
 * Send a msg to the NPE and wait for a reply.  We spin as
 * we may be called early with interrupts not properly setup.
 */
int
ixpnpe_sendandrecvmsg_sync(struct ixpnpe_softc *sc,
	const uint32_t send[2], uint32_t recv[2])
{
	int error;

	mtx_lock(&sc->sc_mtx);
	error = putmsg(sc, send);
	if (error == 0)
		error = getmsg(sc, recv);
	mtx_unlock(&sc->sc_mtx);

	return error;
}

/*
 * Send a msg to the NPE w/o waiting for a reply.
 */
int
ixpnpe_sendmsg_async(struct ixpnpe_softc *sc, const uint32_t msg[2])
{
	int error;

	mtx_lock(&sc->sc_mtx);
	error = putmsg(sc, msg);
	mtx_unlock(&sc->sc_mtx);

	return error;
}

static int
recvmsg_locked(struct ixpnpe_softc *sc, uint32_t msg[2])
{
	mtx_assert(&sc->sc_mtx, MA_OWNED);

	DPRINTF(sc->sc_dev, "%s: msgwaiting %d\n", __func__, sc->sc_msgwaiting);
	if (sc->sc_msgwaiting) {
		msg[0] = sc->sc_msg[0];
		msg[1] = sc->sc_msg[1];
		sc->sc_msgwaiting = 0;
		return 0;
	}
	return EAGAIN;
}

/*
 * Receive any msg previously received from the NPE. If nothing
 * is available we return EAGAIN and the caller is required to
 * do a synchronous receive or try again later.
 */
int
ixpnpe_recvmsg_async(struct ixpnpe_softc *sc, uint32_t msg[2])
{
	int error;

	mtx_lock(&sc->sc_mtx);
	error = recvmsg_locked(sc, msg);
	mtx_unlock(&sc->sc_mtx);

	return error;
}

/*
 * Receive a msg from the NPE.  If one was received asynchronously
 * then it's returned; otherwise we poll synchronously.
 */
int
ixpnpe_recvmsg_sync(struct ixpnpe_softc *sc, uint32_t msg[2])
{
	int error;

	mtx_lock(&sc->sc_mtx);
	error = recvmsg_locked(sc, msg);
	if (error == EAGAIN)
		error = getmsg(sc, msg);
	mtx_unlock(&sc->sc_mtx);

	return error;
}
