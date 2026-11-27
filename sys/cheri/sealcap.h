/*-
 * Copyright (c) 2026 Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Capabilities Limited with funding from
 * Innovate UK and the Department for Science, Innovation and Technology
 * for the adoption and diffusion of CHERI technology under project
 * 10168042 (“CheriBSD feature extraction, maturity, and testing”).
 * 
 */

#ifndef __SYS_CHERI_SEALCAP_H__
#define	__SYS_CHERI_SEALCAP_H__

#ifndef _KERNEL
int	cheri_sealcap_alloc(__uintcap_t *sealcap);
#endif

#endif /* __SYS_CHERI_SEALCAP_H__ */
