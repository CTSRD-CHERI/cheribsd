/*
 * Copyright 2019 Emmanuel Vadot <manu@freebsd.org>
 * Copyright (c) 2017 Ian Lepore <ian@freebsd.org> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _MMC_FDT_HELPERS_H_
#define	_MMC_FDT_HELPERS_H_

#include <dev/gpio/gpiobusvar.h>
#include <dev/ofw/ofw_bus.h>

#ifdef EXT_RESOURCES
#include <dev/extres/regulator/regulator.h>
#endif

struct mmc_fdt_helper {
	device_t		dev;
	gpio_pin_t		wp_pin;
	gpio_pin_t		cd_pin;
	void *			cd_ihandler;
	struct resource *	cd_ires;
	int			cd_irid;
	void			(*cd_handler)(device_t, bool);
	struct timeout_task	cd_delayed_task;
	bool			cd_disabled;
	bool			wp_disabled;
	bool			cd_present;
	uint32_t		props;
#define	MMC_PROP_BROKEN_CD	(1 << 0)
#define	MMC_PROP_NON_REMOVABLE	(1 << 1)
#define	MMC_PROP_WP_INVERTED	(1 << 2)
#define	MMC_PROP_CD_INVERTED	(1 << 3)
#define	MMC_PROP_DISABLE_WP	(1 << 4)
#define	MMC_PROP_NO_SDIO	(1 << 5)
#define	MMC_PROP_NO_SD		(1 << 6)
#define	MMC_PROP_NO_MMC		(1 << 7)

#ifdef EXT_RESOURCES
	regulator_t	vmmc_supply;
	regulator_t	vqmmc_supply;
#endif
};

typedef void (*mmc_fdt_cd_handler)(device_t dev, bool present);

int mmc_fdt_parse(device_t dev, phandle_t node, struct mmc_fdt_helper *helper, struct mmc_host *host);
int mmc_fdt_gpio_setup(device_t dev, phandle_t node, struct mmc_fdt_helper *helper, mmc_fdt_cd_handler handler);
void mmc_fdt_gpio_teardown(struct mmc_fdt_helper *helper);
bool mmc_fdt_gpio_get_present(struct mmc_fdt_helper *helper);
bool mmc_fdt_gpio_get_readonly(struct mmc_fdt_helper *helper);

#endif
