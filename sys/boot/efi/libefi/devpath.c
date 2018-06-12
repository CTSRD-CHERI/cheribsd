/*-
 * Copyright (c) 2016 John Baldwin <jhb@FreeBSD.org>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <efi.h>
#include <efilib.h>

static EFI_GUID ImageDevicePathGUID =
    EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID;
static EFI_GUID DevicePathGUID = DEVICE_PATH_PROTOCOL;
static EFI_GUID DevicePathToTextGUID = EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;
static EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *textProtocol;

EFI_DEVICE_PATH *
efi_lookup_image_devpath(EFI_HANDLE handle)
{
	EFI_DEVICE_PATH *devpath;
	EFI_STATUS status;

	status = BS->HandleProtocol(handle, &ImageDevicePathGUID,
	    (VOID **)&devpath);
	if (EFI_ERROR(status))
		devpath = NULL;
	return (devpath);
}

EFI_DEVICE_PATH *
efi_lookup_devpath(EFI_HANDLE handle)
{
	EFI_DEVICE_PATH *devpath;
	EFI_STATUS status;

	status = BS->HandleProtocol(handle, &DevicePathGUID, (VOID **)&devpath);
	if (EFI_ERROR(status))
		devpath = NULL;
	return (devpath);
}

CHAR16 *
efi_devpath_name(EFI_DEVICE_PATH *devpath)
{
	static int once = 1;
	EFI_STATUS status;

	if (devpath == NULL)
		return (NULL);
	if (once) {
		status = BS->LocateProtocol(&DevicePathToTextGUID, NULL,
		    (VOID **)&textProtocol);
		if (EFI_ERROR(status))
			textProtocol = NULL;
		once = 0;
	}
	if (textProtocol == NULL)
		return (NULL);

	return (textProtocol->ConvertDevicePathToText(devpath, TRUE, TRUE));
}

void
efi_free_devpath_name(CHAR16 *text)
{

	BS->FreePool(text);
}

EFI_DEVICE_PATH *
efi_devpath_last_node(EFI_DEVICE_PATH *devpath)
{

	if (IsDevicePathEnd(devpath))
		return (NULL);
	while (!IsDevicePathEnd(NextDevicePathNode(devpath)))
		devpath = NextDevicePathNode(devpath);
	return (devpath);
}

EFI_DEVICE_PATH *
efi_devpath_trim(EFI_DEVICE_PATH *devpath)
{
	EFI_DEVICE_PATH *node, *copy;
	size_t prefix, len;

	if ((node = efi_devpath_last_node(devpath)) == NULL)
		return (NULL);
	prefix = (UINT8 *)node - (UINT8 *)devpath;
	if (prefix == 0)
		return (NULL);
	len = prefix + DevicePathNodeLength(NextDevicePathNode(node));
	copy = malloc(len);
	if (copy != NULL) {
		memcpy(copy, devpath, prefix);
		node = (EFI_DEVICE_PATH *)((UINT8 *)copy + prefix);
		SetDevicePathEndNode(node);
	}
	return (copy);
}

EFI_HANDLE
efi_devpath_handle(EFI_DEVICE_PATH *devpath)
{
	EFI_STATUS status;
	EFI_HANDLE h;

	/*
	 * There isn't a standard way to locate a handle for a given
	 * device path.  However, querying the EFI_DEVICE_PATH protocol
	 * for a given device path should give us a handle for the
	 * closest node in the path to the end that is valid.
	 */
	status = BS->LocateDevicePath(&DevicePathGUID, &devpath, &h);
	if (EFI_ERROR(status))
		return (NULL);
	return (h);
}

bool
efi_devpath_match(EFI_DEVICE_PATH *devpath1, EFI_DEVICE_PATH *devpath2)
{
	size_t len;

	if (devpath1 == NULL || devpath2 == NULL)
		return (false);

	while (true) {
		if (DevicePathType(devpath1) != DevicePathType(devpath2) ||
		    DevicePathSubType(devpath1) != DevicePathSubType(devpath2))
			return (false);

		len = DevicePathNodeLength(devpath1);
		if (len != DevicePathNodeLength(devpath2))
			return (false);

		if (memcmp(devpath1, devpath2, len) != 0)
			return (false);

		if (IsDevicePathEnd(devpath1))
			break;
		devpath1 = NextDevicePathNode(devpath1);
		devpath2 = NextDevicePathNode(devpath2);
	}
	return (true);
}

int
efi_devpath_is_prefix(EFI_DEVICE_PATH *prefix, EFI_DEVICE_PATH *path)
{
	int len;

	if (prefix == NULL || path == NULL)
		return (0);

	while (1) {
		if (IsDevicePathEnd(prefix))
			break;

		if (DevicePathType(prefix) != DevicePathType(path) ||
		    DevicePathSubType(prefix) != DevicePathSubType(path))
			return (0);

		len = DevicePathNodeLength(prefix);
		if (len != DevicePathNodeLength(path))
			return (0);

		if (memcmp(prefix, path, (size_t)len) != 0)
			return (0);

		prefix = NextDevicePathNode(prefix);
		path = NextDevicePathNode(path);
	}
	return (1);
}
