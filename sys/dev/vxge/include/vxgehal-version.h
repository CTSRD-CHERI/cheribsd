/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2002-2011 Exar Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification are permitted provided the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    3. Neither the name of the Exar Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*$FreeBSD$*/

#ifndef	VXGE_HAL_VERSION_H
#define	VXGE_HAL_VERSION_H

#include <dev/vxge/include/build-version.h>


/*
 * VXGE_HAL_VERSION_MAJOR - HAL major version
 */
#define	VXGE_HAL_VERSION_MAJOR		0

/*
 * VXGE_HAL_VERSION_MINOR - HAL minor version
 */
#define	VXGE_HAL_VERSION_MINOR		0

/*
 * VXGE_HAL_VERSION_FIX - HAL version fix
 */
#define	VXGE_HAL_VERSION_FIX		0

/*
 * VXGE_HAL_VERSION_BUILD - HAL build version
 */
#define	VXGE_HAL_VERSION_BUILD	GENERATED_BUILD_VERSION

/*
 * VXGE_HAL_VERSION - HAL version
 */
#define	VXGE_HAL_VERSION "VXGE_HAL_VERSION_MAJOR.VXGE_HAL_VERSION_MINOR.\
			VXGE_HAL_VERSION_FIX.VXGE_HAL_VERSION_BUILD"

/*
 * VXGE_HAL_DESC - HAL Description
 */
#define	VXGE_HAL_DESC	VXGE_DRIVER_NAME" v."VXGE_HAL_VERSION

/* Link Layer versioning */
#include <dev/vxge/vxgell-version.h>

#endif	/* VXGE_HAL_VERSION_H */
