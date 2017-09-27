/*-
 * Copyright (c) 2017 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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


#ifndef _CHERIABI_DTRACE_H_
#define _CHERIABI_DTRACE_H_

#include <dtrace_types.h>

typedef struct dtrace_bufdesc_c {
	uint64_t dtbd_size;			/* size of buffer */
	uint32_t dtbd_cpu;			/* CPU or DTRACE_CPUALL */
	uint32_t dtbd_errors;			/* number of errors */
	uint64_t dtbd_drops;			/* number of drops */
	char * __capability dtbd_data;		/* data */
	uint64_t dtbd_oldest;			/* offset of oldest record */
	uint64_t dtbd_timestamp;		/* hrtime of snapshot */
} dtrace_bufdesc_c_t;

typedef struct {
	void * __capability dof;
	int n_matched;
} dtrace_enable_io_c_t;

typedef struct dtrace_aggdesc_c {
	char * __capability dtagd_name;		/* not filled in by kernel */
	dtrace_aggvarid_t dtagd_varid;		/* not filled in by kernel */
	int dtagd_flags;			/* not filled in by kernel */
	dtrace_aggid_t dtagd_id;		/* aggregation ID */
	dtrace_epid_t dtagd_epid;		/* enabled probe ID */
	uint32_t dtagd_size;			/* size in bytes */
	int dtagd_nrecs;			/* number of records */
	uint32_t dtagd_pad;			/* explicit padding */
	dtrace_recdesc_t dtagd_rec[1];		/* record descriptions */
} dtrace_aggdesc_c_t;

typedef struct dtrace_fmtdesc_c {
	char * __capability dtfd_string;	/* format string */
	int dtfd_length;			/* length of format string */
	uint16_t dtfd_format;			/* format identifier */
} dtrace_fmtdesc_c_t;

typedef struct dtrace_eprobedesc_c {
	dtrace_epid_t dtepd_epid;		/* enabled probe ID */
	dtrace_id_t dtepd_probeid;		/* probe ID */
	__uintcap_t dtepd_uarg;			/* library argument */
	uint32_t dtepd_size;			/* total size */
	int dtepd_nrecs;			/* number of records */
	dtrace_recdesc_t dtepd_rec[1];		/* records themselves */
} dtrace_eprobedesc_c_t;

#define	DTRACEIOC_BUFSNAP_C	_IOC_NEWTYPE(DTRACEIOC_BUFSNAP, dtrace_bufdesc_c_t * __capability)
#define	DTRACEIOC_ENABLE_C	_IOC_NEWTYPE(DTRACEIOC_ENABLE, dtrace_enable_io_c_t)
#define	DTRACEIOC_AGGSNAP_C	_IOC_NEWTYPE(DTRACEIOC_AGGSNAP, dtrace_bufdesc_c_t * __capability)
#define	DTRACEIOC_AGGDESC_C	_IOC_NEWTYPE(DTRACEIOC_AGGDESC, dtrace_aggdesc_c_t * __capability)
#define	DTRACEIOC_FORMAT_C	_IOC_NEWTYPE(DTRACEIOC_FORMAT, dtrace_fmtdesc_c_t)
#define	DTRACEIOC_DOFGET_C	_IOC_NEWTYPE(DTRACEIOC_DOFGET, dof_hdr_t * __capability)
#define	DTRACEIOC_EPROBE_C	_IOC_NEWTYPE(DTRACEIOC_EPROBE, dtrace_eprobedesc_c_t * __capability)


int	cheriabi_dtrace_in(u_long, void *, u_long *, void **);
int	cheriabi_dtrace_out(u_long, void *, void *);

#endif /* _CHERIABI_DTRACE_H_ */
