/* $FreeBSD$ */
/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2008 Hans Petter Selasky <hselasky@FreeBSD.org>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This file contains the USB templates for an USB Media Transfer
 * Protocol device.
 *
 * NOTE: It is common practice that MTP devices use some dummy
 * descriptor cludges to be automatically detected by the host
 * operating system. These descriptors are documented in the LibMTP
 * library at sourceforge.net. The alternative is to supply the host
 * operating system the VID and PID of your device.
 */

#ifdef USB_GLOBAL_INCLUDE_FILE
#include USB_GLOBAL_INCLUDE_FILE
#else
#include <sys/stdint.h>
#include <sys/stddef.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/unistd.h>
#include <sys/callout.h>
#include <sys/malloc.h>
#include <sys/priv.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usb_core.h>

#include <dev/usb/template/usb_template.h>
#endif			/* USB_GLOBAL_INCLUDE_FILE */

#define	MTP_BREQUEST 0x08

enum {
	STRING_LANG_INDEX,
	STRING_MTP_DATA_INDEX,
	STRING_MTP_CONFIG_INDEX,
	STRING_MTP_VENDOR_INDEX,
	STRING_MTP_PRODUCT_INDEX,
	STRING_MTP_SERIAL_INDEX,
	STRING_MTP_MAX,
};

#define	STRING_MTP_DATA	\
  "U\0S\0B\0 \0M\0T\0P\0 \0I\0n\0t\0e\0r\0f\0a\0c\0e"

#define	STRING_MTP_CONFIG \
  "D\0e\0f\0a\0u\0l\0t\0 \0c\0o\0n\0f\0i\0g"

#define	STRING_MTP_VENDOR \
  "F\0r\0e\0e\0B\0S\0D\0 \0f\0o\0u\0n\0d\0a\0t\0i\0o\0n"

#define	STRING_MTP_PRODUCT \
  "U\0S\0B\0 \0M\0T\0P"

#define	STRING_MTP_SERIAL \
  "J\0u\0n\0e\0 \0002\0000\0000\08"

/* make the real string descriptors */

USB_MAKE_STRING_DESC(STRING_MTP_DATA, string_mtp_data);
USB_MAKE_STRING_DESC(STRING_MTP_CONFIG, string_mtp_config);
USB_MAKE_STRING_DESC(STRING_MTP_VENDOR, string_mtp_vendor);
USB_MAKE_STRING_DESC(STRING_MTP_PRODUCT, string_mtp_product);
USB_MAKE_STRING_DESC(STRING_MTP_SERIAL, string_mtp_serial);

/* prototypes */

static usb_temp_get_string_desc_t mtp_get_string_desc;
static usb_temp_get_vendor_desc_t mtp_get_vendor_desc;

static const struct usb_temp_packet_size bulk_mps = {
	.mps[USB_SPEED_FULL] = 64,
	.mps[USB_SPEED_HIGH] = 512,
};

static const struct usb_temp_packet_size intr_mps = {
	.mps[USB_SPEED_FULL] = 64,
	.mps[USB_SPEED_HIGH] = 64,
};

static const struct usb_temp_endpoint_desc bulk_out_ep = {
	.pPacketSize = &bulk_mps,
#ifdef USB_HIP_OUT_EP_0
	.bEndpointAddress = USB_HIP_OUT_EP_0,
#else
	.bEndpointAddress = UE_DIR_OUT,
#endif
	.bmAttributes = UE_BULK,
};

static const struct usb_temp_endpoint_desc intr_in_ep = {
	.pPacketSize = &intr_mps,
	.bEndpointAddress = UE_DIR_IN,
	.bmAttributes = UE_INTERRUPT,
};

static const struct usb_temp_endpoint_desc bulk_in_ep = {
	.pPacketSize = &bulk_mps,
#ifdef USB_HIP_IN_EP_0
	.bEndpointAddress = USB_HIP_IN_EP_0,
#else
	.bEndpointAddress = UE_DIR_IN,
#endif
	.bmAttributes = UE_BULK,
};

static const struct usb_temp_endpoint_desc *mtp_data_endpoints[] = {
	&bulk_in_ep,
	&bulk_out_ep,
	&intr_in_ep,
	NULL,
};

static const struct usb_temp_interface_desc mtp_data_interface = {
	.ppEndpoints = mtp_data_endpoints,
	.bInterfaceClass = UICLASS_IMAGE,
	.bInterfaceSubClass = UISUBCLASS_SIC,	/* Still Image Class */
	.bInterfaceProtocol = 1,	/* PIMA 15740 */
	.iInterface = STRING_MTP_DATA_INDEX,
};

static const struct usb_temp_interface_desc *mtp_interfaces[] = {
	&mtp_data_interface,
	NULL,
};

static const struct usb_temp_config_desc mtp_config_desc = {
	.ppIfaceDesc = mtp_interfaces,
	.bmAttributes = UC_BUS_POWERED,
	.bMaxPower = 25,		/* 50 mA */
	.iConfiguration = STRING_MTP_CONFIG_INDEX,
};

static const struct usb_temp_config_desc *mtp_configs[] = {
	&mtp_config_desc,
	NULL,
};

const struct usb_temp_device_desc usb_template_mtp = {
	.getStringDesc = &mtp_get_string_desc,
	.getVendorDesc = &mtp_get_vendor_desc,
	.ppConfigDesc = mtp_configs,
	.idVendor = USB_TEMPLATE_VENDOR,
	.idProduct = 0x0011,
	.bcdDevice = 0x0100,
	.bDeviceClass = 0,
	.bDeviceSubClass = 0,
	.bDeviceProtocol = 0,
	.iManufacturer = STRING_MTP_VENDOR_INDEX,
	.iProduct = STRING_MTP_PRODUCT_INDEX,
	.iSerialNumber = STRING_MTP_SERIAL_INDEX,
};

/*------------------------------------------------------------------------*
 *	mtp_get_vendor_desc
 *
 * Return values:
 * NULL: Failure. No such vendor descriptor.
 * Else: Success. Pointer to vendor descriptor is returned.
 *------------------------------------------------------------------------*/
static const void *
mtp_get_vendor_desc(const struct usb_device_request *req, uint16_t *plen)
{
	static const uint8_t dummy_desc[0x28] = {
		0x28, 0, 0, 0, 0, 1, 4, 0,
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 0x4D, 0x54, 0x50, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	};

	if ((req->bmRequestType == UT_READ_VENDOR_DEVICE) &&
	    (req->bRequest == MTP_BREQUEST) && (req->wValue[0] == 0) &&
	    (req->wValue[1] == 0) && (req->wIndex[1] == 0) &&
	    ((req->wIndex[0] == 4) || (req->wIndex[0] == 5))) {
		/*
		 * By returning this descriptor LibMTP will
		 * automatically pickup our device.
		 */
		return (dummy_desc);
	}
	return (NULL);
}

/*------------------------------------------------------------------------*
 *	mtp_get_string_desc
 *
 * Return values:
 * NULL: Failure. No such string.
 * Else: Success. Pointer to string descriptor is returned.
 *------------------------------------------------------------------------*/
static const void *
mtp_get_string_desc(uint16_t lang_id, uint8_t string_index)
{
	static const void *ptr[STRING_MTP_MAX] = {
		[STRING_LANG_INDEX] = &usb_string_lang_en,
		[STRING_MTP_DATA_INDEX] = &string_mtp_data,
		[STRING_MTP_CONFIG_INDEX] = &string_mtp_config,
		[STRING_MTP_VENDOR_INDEX] = &string_mtp_vendor,
		[STRING_MTP_PRODUCT_INDEX] = &string_mtp_product,
		[STRING_MTP_SERIAL_INDEX] = &string_mtp_serial,
	};

	static const uint8_t dummy_desc[0x12] = {
		0x12, 0x03, 0x4D, 0x00, 0x53, 0x00, 0x46, 0x00,
		0x54, 0x00, 0x31, 0x00, 0x30, 0x00, 0x30, 0x00,
		MTP_BREQUEST, 0x00,
	};

	if (string_index == 0xEE) {
		/*
		 * By returning this string LibMTP will automatically
		 * pickup our device.
		 */
		return (dummy_desc);
	}
	if (string_index == 0) {
		return (&usb_string_lang_en);
	}
	if (lang_id != 0x0409) {
		return (NULL);
	}
	if (string_index < STRING_MTP_MAX) {
		return (ptr[string_index]);
	}
	return (NULL);
}
