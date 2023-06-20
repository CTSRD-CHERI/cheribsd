/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin Köhne <c.koehne@beckhoff.com>
 */

#include <sys/param.h>
#include <sys/endian.h>

#include <machine/vmm.h>

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "acpi_device.h"
#include "inout.h"
#include "qemu_fwcfg.h"

#define QEMU_FWCFG_ACPI_DEVICE_NAME "FWCF"
#define QEMU_FWCFG_ACPI_HARDWARE_ID "QEMU0002"

#define QEMU_FWCFG_SELECTOR_PORT_NUMBER 0x510
#define QEMU_FWCFG_SELECTOR_PORT_SIZE 1
#define QEMU_FWCFG_SELECTOR_PORT_FLAGS IOPORT_F_INOUT
#define QEMU_FWCFG_DATA_PORT_NUMBER 0x511
#define QEMU_FWCFG_DATA_PORT_SIZE 1
#define QEMU_FWCFG_DATA_PORT_FLAGS \
	IOPORT_F_INOUT /* QEMU v2.4+ ignores writes */

#define QEMU_FWCFG_ARCHITECTURE_MASK 0x0001
#define QEMU_FWCFG_INDEX_MASK 0x3FFF

#define QEMU_FWCFG_SELECT_READ 0
#define QEMU_FWCFG_SELECT_WRITE 1

#define QEMU_FWCFG_ARCHITECTURE_GENERIC 0
#define QEMU_FWCFG_ARCHITECTURE_SPECIFIC 1

#define QEMU_FWCFG_INDEX_SIGNATURE 0x00
#define QEMU_FWCFG_INDEX_ID 0x01
#define QEMU_FWCFG_INDEX_FILE_DIR 0x19

#define QEMU_FWCFG_MIN_FILES 10

#pragma pack(1)

union qemu_fwcfg_selector {
	struct {
		uint16_t index : 14;
		uint16_t writeable : 1;
		uint16_t architecture : 1;
	};
	uint16_t bits;
};

struct qemu_fwcfg_signature {
	uint8_t signature[4];
};

struct qemu_fwcfg_id {
	uint32_t interface : 1; /* always set */
	uint32_t DMA : 1;
	uint32_t reserved : 30;
};

struct qemu_fwcfg_file {
	uint32_t be_size;
	uint16_t be_selector;
	uint16_t reserved;
	uint8_t name[QEMU_FWCFG_MAX_NAME];
};

struct qemu_fwcfg_directory {
	uint32_t be_count;
	struct qemu_fwcfg_file files[0];
};

#pragma pack()

struct qemu_fwcfg_softc {
	struct acpi_device *acpi_dev;

	uint32_t data_offset;
	union qemu_fwcfg_selector selector;
	struct qemu_fwcfg_item items[QEMU_FWCFG_MAX_ARCHS]
				    [QEMU_FWCFG_MAX_ENTRIES];
};

static struct qemu_fwcfg_softc fwcfg_sc;

static int
qemu_fwcfg_selector_port_handler(struct vmctx *const ctx __unused, const int in,
    const int port __unused, const int bytes, uint32_t *const eax,
    void *const arg __unused)
{
	if (bytes != sizeof(uint16_t)) {
		warnx("%s: invalid size (%d) of IO port access", __func__,
		    bytes);
		return (-1);
	}

	if (in) {
		*eax = htole16(fwcfg_sc.selector.bits);
		return (0);
	}

	fwcfg_sc.data_offset = 0;
	fwcfg_sc.selector.bits = le16toh(*eax);

	return (0);
}

static int
qemu_fwcfg_data_port_handler(struct vmctx *const ctx __unused, const int in,
    const int port __unused, const int bytes, uint32_t *const eax,
    void *const arg __unused)
{
	if (bytes != sizeof(uint8_t)) {
		warnx("%s: invalid size (%d) of IO port access", __func__,
		    bytes);
		return (-1);
	}

	if (!in) {
		warnx("%s: Writes to qemu fwcfg data port aren't allowed",
		    __func__);
		return (-1);
	}

	/* get fwcfg item */
	struct qemu_fwcfg_item *const item =
	    &fwcfg_sc.items[fwcfg_sc.selector.architecture]
			   [fwcfg_sc.selector.index];
	if (item->data == NULL) {
		warnx(
		    "%s: qemu fwcfg item doesn't exist (architecture %s index 0x%x)",
		    __func__,
		    fwcfg_sc.selector.architecture ? "specific" : "generic",
		    fwcfg_sc.selector.index);
		*eax = 0x00;
		return (0);
	} else if (fwcfg_sc.data_offset >= item->size) {
		warnx(
		    "%s: qemu fwcfg item read exceeds size (architecture %s index 0x%x size 0x%x offset 0x%x)",
		    __func__,
		    fwcfg_sc.selector.architecture ? "specific" : "generic",
		    fwcfg_sc.selector.index, item->size, fwcfg_sc.data_offset);
		*eax = 0x00;
		return (0);
	}

	/* return item data */
	*eax = item->data[fwcfg_sc.data_offset];
	fwcfg_sc.data_offset++;

	return (0);
}

static int
qemu_fwcfg_add_item(const uint16_t architecture, const uint16_t index,
    const uint32_t size, void *const data)
{
	/* truncate architecture and index to their desired size */
	const uint16_t arch = architecture & QEMU_FWCFG_ARCHITECTURE_MASK;
	const uint16_t idx = index & QEMU_FWCFG_INDEX_MASK;

	/* get pointer to item specified by selector */
	struct qemu_fwcfg_item *const fwcfg_item = &fwcfg_sc.items[arch][idx];

	/* check if item is already used */
	if (fwcfg_item->data != NULL) {
		warnx("%s: qemu fwcfg item exists (architecture %s index 0x%x)",
		    __func__, arch ? "specific" : "generic", idx);
		return (-1);
	}

	/* save data of the item */
	fwcfg_item->size = size;
	fwcfg_item->data = data;

	return (0);
}

static int
qemu_fwcfg_add_item_file_dir(void)
{
	const size_t size = sizeof(struct qemu_fwcfg_directory) +
	    QEMU_FWCFG_MIN_FILES * sizeof(struct qemu_fwcfg_file);
	struct qemu_fwcfg_directory *const fwcfg_directory = calloc(1, size);
	if (fwcfg_directory == NULL) {
		return (ENOMEM);
	}

	fwcfg_sc.directory = fwcfg_directory;

	return (qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_FILE_DIR, sizeof(struct qemu_fwcfg_directory),
	    (uint8_t *)fwcfg_sc.directory));
}

static int
qemu_fwcfg_add_item_id(void)
{
	struct qemu_fwcfg_id *const fwcfg_id = calloc(1,
	    sizeof(struct qemu_fwcfg_id));
	if (fwcfg_id == NULL) {
		return (ENOMEM);
	}

	fwcfg_id->interface = 1;
	fwcfg_id->DMA = 0;

	uint32_t *const le_fwcfg_id_ptr = (uint32_t *)fwcfg_id;
	*le_fwcfg_id_ptr = htole32(*le_fwcfg_id_ptr);

	return (qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_ID, sizeof(struct qemu_fwcfg_id),
	    (uint8_t *)fwcfg_id));
}

static int
qemu_fwcfg_add_item_signature(void)
{
	struct qemu_fwcfg_signature *const fwcfg_signature = calloc(1,
	    sizeof(struct qemu_fwcfg_signature));
	if (fwcfg_signature == NULL) {
		return (ENOMEM);
	}

	fwcfg_signature->signature[0] = 'Q';
	fwcfg_signature->signature[1] = 'E';
	fwcfg_signature->signature[2] = 'M';
	fwcfg_signature->signature[3] = 'U';

	return (qemu_fwcfg_add_item(QEMU_FWCFG_ARCHITECTURE_GENERIC,
	    QEMU_FWCFG_INDEX_SIGNATURE, sizeof(struct qemu_fwcfg_signature),
	    (uint8_t *)fwcfg_signature));
}

static int
qemu_fwcfg_register_port(const char *const name, const int port, const int size,
    const int flags, const inout_func_t handler)
{
	struct inout_port iop;

	bzero(&iop, sizeof(iop));
	iop.name = name;
	iop.port = port;
	iop.size = size;
	iop.flags = flags;
	iop.handler = handler;

	return (register_inout(&iop));
}

int
qemu_fwcfg_init(struct vmctx *const ctx)
{
	int error;

	error = acpi_device_create(&fwcfg_sc.acpi_dev, ctx,
	    QEMU_FWCFG_ACPI_DEVICE_NAME, QEMU_FWCFG_ACPI_HARDWARE_ID);
	if (error) {
		warnx("%s: failed to create ACPI device for QEMU FwCfg",
		    __func__);
		goto done;
	}

	error = acpi_device_add_res_fixed_ioport(fwcfg_sc.acpi_dev,
	    QEMU_FWCFG_SELECTOR_PORT_NUMBER, 2);
	if (error) {
		warnx("%s: failed to add fixed IO port for QEMU FwCfg",
		    __func__);
		goto done;
	}

	/* add handlers for fwcfg ports */
	if ((error = qemu_fwcfg_register_port("qemu_fwcfg_selector",
	    QEMU_FWCFG_SELECTOR_PORT_NUMBER, QEMU_FWCFG_SELECTOR_PORT_SIZE,
	    QEMU_FWCFG_SELECTOR_PORT_FLAGS,
	    qemu_fwcfg_selector_port_handler)) != 0) {
		warnx("%s: Unable to register qemu fwcfg selector port 0x%x",
		    __func__, QEMU_FWCFG_SELECTOR_PORT_NUMBER);
		goto done;
	}
	if ((error = qemu_fwcfg_register_port("qemu_fwcfg_data",
	    QEMU_FWCFG_DATA_PORT_NUMBER, QEMU_FWCFG_DATA_PORT_SIZE,
	    QEMU_FWCFG_DATA_PORT_FLAGS, qemu_fwcfg_data_port_handler)) != 0) {
		warnx("%s: Unable to register qemu fwcfg data port 0x%x",
		    __func__, QEMU_FWCFG_DATA_PORT_NUMBER);
		goto done;
	}

	/* add common fwcfg items */
	if ((error = qemu_fwcfg_add_item_signature()) != 0) {
		warnx("%s: Unable to add signature item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_id()) != 0) {
		warnx("%s: Unable to add id item", __func__);
		goto done;
	}
	if ((error = qemu_fwcfg_add_item_file_dir()) != 0) {
		warnx("%s: Unable to add file_dir item", __func__);
		goto done;
	}

done:
	if (error) {
		acpi_device_destroy(fwcfg_sc.acpi_dev);
	}

	return (error);
}
