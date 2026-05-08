/*-
 * Copyright (c) 2026 Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Capabilities Limited with funding from
 * Innovate UK and the Department for Science, Innovation and Technology
 * for the adoption and diffusion of CHERI technology under project
 * 10168042 (“CheriBSD feature extraction, maturity, and testing”).
 */

#include <stdlib.h>

#pragma GCC diagnostic ignored "-Wunused-parameter"

void * __malloc(size_t);

void *
malloc_no_quarantine(size_t s)
{
	return (__malloc(s));
}
