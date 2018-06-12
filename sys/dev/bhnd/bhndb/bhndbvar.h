/*-
 * Copyright (c) 2015-2016 Landon Fuller <landon@landonf.org>
 * Copyright (c) 2017 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by Landon Fuller
 * under sponsorship from the FreeBSD Foundation.
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
 * 
 * $FreeBSD$
 */

#ifndef _BHND_BHNDBVAR_H_
#define _BHND_BHNDBVAR_H_

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/rman.h>

#include <dev/bhnd/bhndvar.h>
#include "bhndb.h"

#include "bhndb_if.h"

/*
 * Definitions shared by bhndb(4) driver implementations.
 */

DECLARE_CLASS(bhndb_driver);

struct bhndb_resources;
struct bhndb_host_resources;

int				 bhndb_attach(device_t dev,
				     struct bhnd_chipid *cid,
				     struct bhnd_core_info *cores, u_int ncores,
				     struct bhnd_core_info *bridge_core,
				     bhnd_erom_class_t *erom_class);

int				 bhndb_generic_probe(device_t dev);
int				 bhndb_generic_detach(device_t dev);
int				 bhndb_generic_suspend(device_t dev);
int				 bhndb_generic_resume(device_t dev);
int				 bhndb_generic_init_full_config(device_t dev,
				     device_t child,
				     const struct bhndb_hw_priority *hw_prio_table);

int				 bhnd_generic_br_suspend_child(device_t dev,
				     device_t child);
int				 bhnd_generic_br_resume_child(device_t dev,
				     device_t child);

int				 bhndb_find_hostb_core(
				     struct bhnd_core_info *cores, u_int ncores,
				     bhnd_devclass_t bridge_devclass,
				     struct bhnd_core_info *core);

int				 bhndb_alloc_host_resources(device_t dev,
				     const struct bhndb_hwcfg *hwcfg,
				     struct bhndb_host_resources **resources);
void				 bhndb_release_host_resources(
				     struct bhndb_host_resources *resources);
struct resource			*bhndb_host_resource_for_range(
				     struct bhndb_host_resources *resources,
				     int type, rman_res_t start, 
				     rman_res_t count);
struct resource			*bhndb_host_resource_for_regwin(
				     struct bhndb_host_resources *resources,
				     const struct bhndb_regwin *win);

size_t				 bhndb_regwin_count(
				     const struct bhndb_regwin *table,
				     bhndb_regwin_type_t type);

const struct bhndb_regwin	*bhndb_regwin_find_type(
				     const struct bhndb_regwin *table,
				     bhndb_regwin_type_t type,
				     bus_size_t min_size);

const struct bhndb_regwin	*bhndb_regwin_find_core(
				     const struct bhndb_regwin *table,
				     bhnd_devclass_t class, int unit,
				     bhnd_port_type port_type, u_int port,
				     u_int region);

const struct bhndb_regwin	*bhndb_regwin_find_best(
				     const struct bhndb_regwin *table,
				     bhnd_devclass_t class, int unit,
				     bhnd_port_type port_type, u_int port,
				     u_int region, bus_size_t min_size);

bool				 bhndb_regwin_match_core(
				     const struct bhndb_regwin *regw,
				     struct bhnd_core_info *core);

/** 
 * bhndb child address space. Children either operate in the bridged
 * SoC address space, or within the address space mapped to the host
 * device (e.g. the PCI BAR(s)).
 */
typedef enum {
	BHNDB_ADDRSPACE_BRIDGED,	/**< bridged (SoC) address space */
	BHNDB_ADDRSPACE_NATIVE		/**< host address space */
} bhndb_addrspace;

/** bhndb child instance state */
struct bhndb_devinfo {
	bhndb_addrspace		addrspace;	/**< child address space. */
	struct resource_list    resources;	/**< child resources. */
};

/**
 * Host resources allocated for a bridge hardware configuration.
 */
struct bhndb_host_resources {
	device_t			 owner;			/**< device owning the allocated resources */
	const struct bhndb_hwcfg	*cfg;			/**< bridge hardware configuration */
	struct resource_spec		*resource_specs;	/**< resource specification table */
	struct resource			**resources;		/**< allocated resource table */
};

/**
 * bhndb driver instance state. Must be first member of all subclass
 * softc structures.
 */
struct bhndb_softc {
	device_t			 dev;		/**< bridge device */
	struct bhnd_chipid		 chipid;	/**< chip identification */
	struct bhnd_core_info		 bridge_core;	/**< bridge core info */

	device_t			 parent_dev;	/**< parent device */
	device_t			 bus_dev;	/**< child bhnd(4) bus */

	struct bhnd_service_registry	 services;	/**< local service registry */

	struct mtx			 sc_mtx;	/**< resource lock. */
	struct bhndb_resources		*bus_res;	/**< bus resource state */
};

#endif /* _BHND_BHNDBVAR_H_ */
