/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 Vladimir Kondratyev <wulf@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libusb.h>

#include "iwmbt_fw.h"
#include "iwmbt_hw.h"
#include "iwmbt_dbg.h"

#define	XMIN(x, y)	((x) < (y) ? (x) : (y))

static int
iwmbt_send_fragment(struct libusb_device_handle *hdl,
    uint8_t fragment_type, const void *data, uint8_t len, int timeout)
{
	int ret, transferred;
	uint8_t buf[IWMBT_HCI_MAX_CMD_SIZE];
	struct iwmbt_hci_cmd *cmd = (struct iwmbt_hci_cmd *) buf;

	memset(buf, 0, sizeof(buf));
	cmd->opcode = htole16(0xfc09),
	cmd->length = len + 1,
	cmd->data[0] = fragment_type;
	memcpy(cmd->data + 1, data, len);

	ret = libusb_bulk_transfer(hdl,
	    IWMBT_BULK_OUT_ENDPOINT_ADDR,
	    (uint8_t *)cmd,
	    IWMBT_HCI_CMD_SIZE(cmd),
	    &transferred,
	    timeout);

	if (ret < 0 || transferred != (int)IWMBT_HCI_CMD_SIZE(cmd)) {
		iwmbt_err("libusb_bulk_transfer() failed: err=%s, size=%zu",
		    libusb_strerror(ret),
		    IWMBT_HCI_CMD_SIZE(cmd));
		return (-1);
	}

	ret = libusb_bulk_transfer(hdl,
	    IWMBT_BULK_IN_ENDPOINT_ADDR,
	    buf,
	    sizeof(buf),
	    &transferred,
	    timeout);

	if (ret < 0) {
		iwmbt_err("libusb_bulk_transfer() failed: err=%s",
		    libusb_strerror(ret));
		return (-1);
	}

	return (0);
}

static int
iwmbt_hci_command(struct libusb_device_handle *hdl, struct iwmbt_hci_cmd *cmd,
    void *event, int size, int *transferred, int timeout)
{
	int ret;

	ret = libusb_control_transfer(hdl,
	    LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_DEVICE,
	    0,
	    0,
	    0,
	    (uint8_t *)cmd,
	    IWMBT_HCI_CMD_SIZE(cmd),
	    timeout);

	if (ret < 0) {
		iwmbt_err("libusb_control_transfer() failed: err=%s",
		    libusb_strerror(ret));
		return (ret);
	}

	ret = libusb_interrupt_transfer(hdl,
	    IWMBT_INTERRUPT_ENDPOINT_ADDR,
	    event,
	    size,
	    transferred,
	    timeout);

	if (ret < 0)
		iwmbt_err("libusb_interrupt_transfer() failed: err=%s",
		    libusb_strerror(ret));

	return (ret);
}

int
iwmbt_load_fwfile(struct libusb_device_handle *hdl,
    const struct iwmbt_firmware *fw, uint32_t *boot_param)
{
	int ready = 0, sent = 0;
	int ret, transferred;
	struct iwmbt_hci_cmd *cmd;
	struct iwmbt_hci_event *event;
	uint8_t buf[IWMBT_HCI_MAX_EVENT_SIZE];

#define	IWMBT_SEND_FRAGMENT(fragment_type, size, msg)	do {		\
	iwmbt_debug("transferring %d bytes, offset %d", size, sent);	\
									\
	ret = iwmbt_send_fragment(hdl,					\
	    fragment_type,						\
	    fw->buf + sent,						\
	    XMIN(size, fw->len - sent),					\
	    IWMBT_HCI_CMD_TIMEOUT);					\
									\
	if (ret < 0) {							\
		iwmbt_debug("Failed to send "msg": code=%d", ret);	\
		return (-1);						\
	}								\
	sent += size;							\
} while (0)

	if (fw->len < 644) {
		iwmbt_err("Invalid size of firmware file (%d)", fw->len);
		return (-1);
	}

	iwmbt_debug("file=%s, size=%d", fw->fwname, fw->len);

	IWMBT_SEND_FRAGMENT(0x00, 0x80, "CCS segment");
	IWMBT_SEND_FRAGMENT(0x03, 0x80, "public key / part 1");
	IWMBT_SEND_FRAGMENT(0x03, 0x80, "public key / part 2");

	/* skip 4 bytes */
	sent += 4;

	IWMBT_SEND_FRAGMENT(0x02, 0x80, "signature / part 1");
	IWMBT_SEND_FRAGMENT(0x02, 0x80, "signature / part 2");

	/*
	 * Send firmware chunks. Chunk len must be 4 byte aligned.
	 * multiple commands can be combined
	 */
	while (fw->len - sent - ready >= (int) sizeof(struct iwmbt_hci_cmd)) {
		cmd = (struct iwmbt_hci_cmd *)(fw->buf + sent + ready);
		/* Parse firmware for Intel Reset HCI command parameter */
		if (cmd->opcode == htole16(0xfc0e)) {
			*boot_param = le32dec(cmd->data);
			iwmbt_debug("boot_param=0x%08x", *boot_param);
		}
		ready += IWMBT_HCI_CMD_SIZE(cmd);
		while (ready >= 0xFC) {
			IWMBT_SEND_FRAGMENT(0x01, 0xFC, "firmware chunk");
			ready -= 0xFC;
		}
		if (ready > 0 && ready % 4 == 0) {
			IWMBT_SEND_FRAGMENT(0x01, ready, "firmware chunk");
			ready = 0;
		}
	}

	/* Wait for firmware download completion event */
	ret = libusb_interrupt_transfer(hdl,
	    IWMBT_INTERRUPT_ENDPOINT_ADDR,
	    buf,
	    sizeof(buf),
	    &transferred,
	    IWMBT_LOADCMPL_TIMEOUT);

	if (ret < 0 || transferred < (int)sizeof(struct iwmbt_hci_event) + 1) {
		iwmbt_err("libusb_interrupt_transfer() failed: "
		    "err=%s, size=%d",
		    libusb_strerror(ret),
		    transferred);
		return (-1);
	}

	/* Expect Vendor Specific Event 0x06 */
	event = (struct iwmbt_hci_event *)buf;
	if (event->header.event != 0xFF || event->data[0] != 0x06) {
		iwmbt_err("firmware download completion event missed");
		return (-1);
	}

	return (0);
}

int
iwmbt_get_version(struct libusb_device_handle *hdl,
    struct iwmbt_version *version)
{
	int ret, transferred;
	struct iwmbt_hci_event_cmd_compl*event;
	struct iwmbt_hci_cmd cmd = {
		.opcode = htole16(0xfc05),
		.length = 0,
	};
	uint8_t buf[IWMBT_HCI_EVT_COMPL_SIZE(struct iwmbt_version)];

	memset(buf, 0, sizeof(buf));

	ret = iwmbt_hci_command(hdl,
	    &cmd,
	    buf,
	    sizeof(buf),
	    &transferred,
	    IWMBT_HCI_CMD_TIMEOUT);

	if (ret < 0 || transferred != sizeof(buf)) {
		 iwmbt_debug("Can't get version: : code=%d, size=%d",
		     ret,
		     transferred);
		 return (-1);
	}

	event = (struct iwmbt_hci_event_cmd_compl *)buf;
	memcpy(version, event->data, sizeof(struct iwmbt_version));

	return (0);
}

int
iwmbt_get_boot_params(struct libusb_device_handle *hdl,
    struct iwmbt_boot_params *params)
{
	int ret, transferred = 0;
	struct iwmbt_hci_event_cmd_compl *event;
	struct iwmbt_hci_cmd cmd = {
		.opcode = htole16(0xfc0d),
		.length = 0,
	};
	uint8_t buf[IWMBT_HCI_EVT_COMPL_SIZE(struct iwmbt_boot_params)];

	memset(buf, 0, sizeof(buf));

	ret = iwmbt_hci_command(hdl,
	    &cmd,
	    buf,
	    sizeof(buf),
	    &transferred,
	    IWMBT_HCI_CMD_TIMEOUT);

	if (ret < 0 || transferred != sizeof(buf)) {
		 iwmbt_debug("Can't get boot params: code=%d, size=%d",
		     ret,
		     transferred);
		 return (-1);
	}

	event = (struct iwmbt_hci_event_cmd_compl *)buf;
	memcpy(params, event->data, sizeof(struct iwmbt_boot_params));

	return (0);
}

int
iwmbt_intel_reset(struct libusb_device_handle *hdl, uint32_t boot_param)
{
	int ret, transferred = 0;
	struct iwmbt_hci_event *event;
	static struct iwmbt_hci_cmd cmd = {
		.opcode = htole16(0xfc01),
		.length = 8,
		.data = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 },
	};
	uint8_t buf[IWMBT_HCI_MAX_EVENT_SIZE];

	le32enc(cmd.data + 4, boot_param);
	memset(buf, 0, sizeof(buf));

	ret = iwmbt_hci_command(hdl,
	    &cmd,
	    buf,
	    sizeof(buf),
	    &transferred,
	    IWMBT_HCI_CMD_TIMEOUT);

	if (ret < 0 || transferred < (int)sizeof(struct iwmbt_hci_event) + 1) {
		 iwmbt_debug("Intel Reset command failed: code=%d, size=%d",
		    ret,
		    transferred);
		 return (ret);
	}

	/* expect Vendor Specific Event 0x02 */
	event = (struct iwmbt_hci_event *)buf;
	if (event->header.event != 0xFF || event->data[0] != 0x02) {
		iwmbt_err("Intel Reset completion event missed");
		return (-1);
	}

	return (0);
}

int
iwmbt_load_ddc(struct libusb_device_handle *hdl,
    const struct iwmbt_firmware *ddc)
{
	int size, sent = 0;
	int ret, transferred;
	uint8_t buf[IWMBT_HCI_MAX_CMD_SIZE];
	struct iwmbt_hci_cmd *cmd = (struct iwmbt_hci_cmd *)buf;

	size = ddc->len;

	iwmbt_debug("file=%s, size=%d", ddc->fwname, size);

	while (size > 0) {

		memset(buf, 0, sizeof(buf));
		cmd->opcode = htole16(0xfc8b);
		cmd->length = ddc->buf[sent] + 1;
		memcpy(cmd->data, ddc->buf + sent, XMIN(ddc->buf[sent], size));

		iwmbt_debug("transferring %d bytes, offset %d",
		    cmd->length,
		    sent);

		size -= cmd->length;
		sent += cmd->length;

		ret = iwmbt_hci_command(hdl,
		    cmd,
		    buf,
		    sizeof(buf),
		    &transferred,
		    IWMBT_HCI_CMD_TIMEOUT);

		if (ret < 0) {
			 iwmbt_debug("Intel Write DDC failed: code=%d", ret);
			 return (-1);
		}
	}

	return (0);
}

int
iwmbt_set_event_mask(struct libusb_device_handle *hdl)
{
	int ret, transferred = 0;
	static struct iwmbt_hci_cmd cmd = {
		.opcode = htole16(0xfc52),
		.length = 8,
		.data = { 0x87, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	};
	uint8_t buf[IWMBT_HCI_MAX_EVENT_SIZE];

	ret = iwmbt_hci_command(hdl,
	    &cmd,
	    buf,
	    sizeof(buf),
	    &transferred,
	    IWMBT_HCI_CMD_TIMEOUT);

	if (ret < 0)
		 iwmbt_debug("Intel Set Event Mask failed: code=%d", ret);

	return (ret);
}
