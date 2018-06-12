/* $FreeBSD$ */
/*-
 * Copyright (c) 2010 Hans Petter Selasky. All rights reserved.
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
 * This file contains the USB template for an USB Keyboard Device.
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
#include <dev/usb/usb_cdc.h>

#include <dev/usb/template/usb_template.h>
#endif			/* USB_GLOBAL_INCLUDE_FILE */

enum {
	INDEX_LANG,
	INDEX_KEYBOARD,
	INDEX_PRODUCT,
	INDEX_MAX,
};

#define	STRING_PRODUCT \
  "K\0e\0y\0b\0o\0a\0r\0d\0 \0T\0e\0s\0t\0 \0D\0e\0v\0i\0c\0e"

#define	STRING_KEYBOARD \
  "K\0e\0y\0b\0o\0a\0r\0d\0 \0i\0n\0t\0e\0r\0f\0a\0c\0e"

/* make the real string descriptors */

USB_MAKE_STRING_DESC(STRING_KEYBOARD, string_keyboard);
USB_MAKE_STRING_DESC(STRING_PRODUCT, string_product);

/* prototypes */

static const struct usb_temp_packet_size keyboard_intr_mps = {
	.mps[USB_SPEED_LOW] = 16,
	.mps[USB_SPEED_FULL] = 16,
	.mps[USB_SPEED_HIGH] = 16,
};

static const struct usb_temp_interval keyboard_intr_interval = {
	.bInterval[USB_SPEED_LOW] = 2,	/* 2 ms */
	.bInterval[USB_SPEED_FULL] = 2,	/* 2 ms */
	.bInterval[USB_SPEED_HIGH] = 5,	/* 2 ms */
};

/* The following HID descriptor was dumped from a HP keyboard. */

static uint8_t keyboard_hid_descriptor[] = {
	0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07,
	0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01,
	0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01,
	0x75, 0x08, 0x81, 0x01, 0x95, 0x03, 0x75, 0x01,
	0x05, 0x08, 0x19, 0x01, 0x29, 0x03, 0x91, 0x02,
	0x95, 0x05, 0x75, 0x01, 0x91, 0x01, 0x95, 0x06,
	0x75, 0x08, 0x15, 0x00, 0x26, 0xff, 0x00, 0x05,
	0x07, 0x19, 0x00, 0x2a, 0xff, 0x00, 0x81, 0x00,
	0xc0
};

static const struct usb_temp_endpoint_desc keyboard_ep_0 = {
	.ppRawDesc = NULL,		/* no raw descriptors */
	.pPacketSize = &keyboard_intr_mps,
	.pIntervals = &keyboard_intr_interval,
	.bEndpointAddress = UE_DIR_IN,
	.bmAttributes = UE_INTERRUPT,
};

static const struct usb_temp_endpoint_desc *keyboard_endpoints[] = {
	&keyboard_ep_0,
	NULL,
};

static const uint8_t keyboard_raw_desc[] = {
	0x09, 0x21, 0x10, 0x01, 0x00, 0x01, 0x22, sizeof(keyboard_hid_descriptor),
	0x00
};

static const void *keyboard_iface_0_desc[] = {
	keyboard_raw_desc,
	NULL,
};

static const struct usb_temp_interface_desc keyboard_iface_0 = {
	.ppRawDesc = keyboard_iface_0_desc,
	.ppEndpoints = keyboard_endpoints,
	.bInterfaceClass = UICLASS_HID,
	.bInterfaceSubClass = UISUBCLASS_BOOT,
	.bInterfaceProtocol = UIPROTO_BOOT_KEYBOARD,
	.iInterface = INDEX_KEYBOARD,
};

static const struct usb_temp_interface_desc *keyboard_interfaces[] = {
	&keyboard_iface_0,
	NULL,
};

static const struct usb_temp_config_desc keyboard_config_desc = {
	.ppIfaceDesc = keyboard_interfaces,
	.bmAttributes = UC_BUS_POWERED,
	.bMaxPower = 25,		/* 50 mA */
	.iConfiguration = INDEX_PRODUCT,
};

static const struct usb_temp_config_desc *keyboard_configs[] = {
	&keyboard_config_desc,
	NULL,
};

static usb_temp_get_string_desc_t keyboard_get_string_desc;
static usb_temp_get_vendor_desc_t keyboard_get_vendor_desc;

const struct usb_temp_device_desc usb_template_kbd = {
	.getStringDesc = &keyboard_get_string_desc,
	.getVendorDesc = &keyboard_get_vendor_desc,
	.ppConfigDesc = keyboard_configs,
	.idVendor = USB_TEMPLATE_VENDOR,
	.idProduct = 0x00CB,
	.bcdDevice = 0x0100,
	.bDeviceClass = UDCLASS_COMM,
	.bDeviceSubClass = 0,
	.bDeviceProtocol = 0,
	.iManufacturer = 0,
	.iProduct = INDEX_PRODUCT,
	.iSerialNumber = 0,
};

/*------------------------------------------------------------------------*
 *      keyboard_get_vendor_desc
 *
 * Return values:
 * NULL: Failure. No such vendor descriptor.
 * Else: Success. Pointer to vendor descriptor is returned.
 *------------------------------------------------------------------------*/
static const void *
keyboard_get_vendor_desc(const struct usb_device_request *req, uint16_t *plen)
{
	if ((req->bmRequestType == 0x81) && (req->bRequest == 0x06) &&
	    (req->wValue[0] == 0x00) && (req->wValue[1] == 0x22) &&
	    (req->wIndex[1] == 0) && (req->wIndex[0] == 0)) {

		*plen = sizeof(keyboard_hid_descriptor);
		return (keyboard_hid_descriptor);
	}
	return (NULL);
}

/*------------------------------------------------------------------------*
 *	keyboard_get_string_desc
 *
 * Return values:
 * NULL: Failure. No such string.
 * Else: Success. Pointer to string descriptor is returned.
 *------------------------------------------------------------------------*/
static const void *
keyboard_get_string_desc(uint16_t lang_id, uint8_t string_index)
{
	static const void *ptr[INDEX_MAX] = {
		[INDEX_LANG] = &usb_string_lang_en,
		[INDEX_KEYBOARD] = &string_keyboard,
		[INDEX_PRODUCT] = &string_product,
	};

	if (string_index == 0) {
		return (&usb_string_lang_en);
	}
	if (lang_id != 0x0409) {
		return (NULL);
	}
	if (string_index < INDEX_MAX) {
		return (ptr[string_index]);
	}
	return (NULL);
}
