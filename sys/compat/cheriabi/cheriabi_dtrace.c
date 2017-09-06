/*-
 * Copyright (c) 2017 Domagoj Stolfa <domagoj.stolfa@cl.cam.ac.uk>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysproto.h>
#include <sys/capsicum.h>
#include <sys/cdio.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/file.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/mdioctl.h>
#include <sys/memrange.h>
#include <sys/pciio.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/user.h>

#include <machine/endian.h>

#include <dtrace_types.h>

#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_proto.h>
/* Must come last due to massive header polution breaking cheriabi_proto.h */
#include <compat/cheriabi/cheriabi_ioctl.h>
#include <compat/cheriabi/cheriabi_dtrace.h>

MALLOC_DECLARE(M_DTRACEIOC);
MALLOC_DEFINE(M_DTRACEIOC, "dtraceioc", "DTrace CheriABI ioctl");

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
	dtrace_recdesc_t *dtagd_rec;		/* record descriptions */
} dtrace_aggdesc_c_t;

typedef struct dtrace_fmtdesc_c {
	char * __capability dtfd_string;	/* format string */
	int dtfd_length;			/* length of format string */
	uint16_t dtfd_format;			/* format identifier */
} dtrace_fmtdesc_c_t;

#define	DTRACEIOC_BUFSNAP_C	_IOC_NEWTYPE(DTRACEIOC_BUFSNAP, dtrace_bufdesc_c_t * __capability)
#define	DTRACEIOC_ENABLE_C	_IOC_NEWTYPE(DTRACEIOC_ENABLE, dtrace_enable_io_c_t)
#define	DTRACEIOC_AGGSNAP_C	_IOC_NEWTYPE(DTRACEIOC_AGGSNAP, dtrace_bufdesc_c_t * __capability)
#define	DTRACEIOC_AGGDESC_C	_IOC_NEWTYPE(DTRACEIOC_AGGDESC, dtrace_aggdesc_c_t * __capability)
#define	DTRACEIOC_FORMAT_C	_IOC_NEWTYPE(DTRACEIOC_FORMAT, dtrace_fmtdesc_c_t)
#define	DTRACEIOC_DOFGET_C	_IOC_NEWTYPE(DTRACEIOC_DOFGET, dof_hdr_t * __capability)

static int
cheriabi_dtrace_ioctl_translate_in(u_long com,
    void *data, u_long *t_comp, void **t_datap)
{
	int error;

	error = 0;

	switch(com) {
	case DTRACEIOC_AGGSNAP_C:
	case DTRACEIOC_BUFSNAP_C: {
		/*
		 * We have to ensure that *pdesc and pdesc is freed on the out
		 * path.
		 */
		dtrace_bufdesc_t **pdesc;
		dtrace_bufdesc_c_t **pdesc_c = (dtrace_bufdesc_c_t **) data;

		error = 0;
		pdesc = malloc(sizeof(dtrace_bufdesc_t *), M_DTRACEIOC, M_WAITOK);
		*pdesc = malloc(sizeof(dtrace_bufdesc_t), M_DTRACEIOC, M_WAITOK);

		*t_datap = pdesc;
		*t_comp = _IOC_NEWTYPE(com, dtrace_bufdesc_t *);

		CP((**pdesc_c), (**pdesc), dtbd_size);
		CP((**pdesc_c), (**pdesc), dtbd_cpu);
		CP((**pdesc_c), (**pdesc), dtbd_errors);
		CP((**pdesc_c), (**pdesc), dtbd_drops);
		CP((**pdesc_c), (**pdesc), dtbd_oldest);
		CP((**pdesc_c), (**pdesc), dtbd_timestamp);
		/*
		 * For dtbd_data, we have to convert the capability to a pointer
		 */
		error = cheriabi_cap_to_ptr((caddr_t *)&((*pdesc)->dtbd_data),
		    (*pdesc_c)->dtbd_data, (*pdesc_c)->dtbd_size,
		    CHERI_PERM_STORE, 0);
	}
	case DTRACEIOC_ENABLE_C: {
		/*
		 * In order to enforce capabilities in this ioctl, we have to
		 * know the information contained in the header. This is not
		 * ideal in any way, shape, or form, as the userspace (which in
		 * theory, is untrusted) is supplying us the information which
		 * we will enforce with the capabilities. This interface likely
		 * needs to be redesigned in a way that can be better enforced.
		 */
		dtrace_enable_io_t *p;
		dtrace_enable_io_c_t *p_c = (dtrace_enable_io_c_t *) data;

		error = 0;
		p = malloc(sizeof(dtrace_enable_io_t), M_DTRACEIOC, M_WAITOK);

		*t_datap = p;
		*t_comp = _IOC_NEWTYPE(com, dtrace_enable_io_t);

		CP((*p_c), (*p), n_matched);

		/*
		 * Check perms.
		 */
		if ((cheri_getperm(p_c->dof) & CHERI_PERM_STORE) != CHERI_PERM_STORE)
			return (EPROT);

		/*
		 * FIXME: No enforcement because we need information from the
		 * header (which is user controlled...).
		 */
		p->dof = (caddr_t) p_c->dof;
		
	}
	case DTRACEIOC_AGGDESC_C: {
		/*
		 * We need to deallocate both *paggdesc and paggdesc.
		 * Furthermore, dtagd_name is a capability but doesn't seem to
		 * be used anywhere in the kernel and likely serves as a thing
		 * to pass to to userspace to identify the aggregations and
		 * pretty-print them. This implies that we need to preserve the
		 * pointer in some way, but we also need to give the capability
		 * back to userspace by preserving it's permissions, length,
		 * offset and so on. This isn't a straightforward thing to do
		 * without being invasing in DTrace itself (which we probably
		 * don't want too much...).
		 */
		dtrace_aggdesc_t **paggdesc;
		/*
		 * We have to enforce __capability on the pointer itself here.
		 */
		dtrace_aggdesc_c_t **paggdesc_c = (dtrace_aggdesc_c_t **) data;

		error = 0;
		paggdesc = malloc(sizeof(dtrace_aggdesc_c_t *), M_DTRACEIOC, M_WAITOK);
		*paggdesc = malloc(sizeof(dtrace_aggdesc_t), M_DTRACEIOC, M_WAITOK);

		*t_datap = paggdesc;
		*t_comp = _IOC_NEWTYPE(com, dtrace_aggdesc_t *);

		CP((**paggdesc_c), (**paggdesc), dtagd_varid);
		CP((**paggdesc_c), (**paggdesc), dtagd_flags);
		CP((**paggdesc_c), (**paggdesc), dtagd_id);
		CP((**paggdesc_c), (**paggdesc), dtagd_epid);
		CP((**paggdesc_c), (**paggdesc), dtagd_size);
		CP((**paggdesc_c), (**paggdesc), dtagd_nrecs);
		CP((**paggdesc_c), (**paggdesc), dtagd_pad);

		/*
		 * dtagd_rec[1] for a pointer, YAY.
		 */
		(*paggdesc)->dtagd_rec = (dtrace_recdesc_t *) (*paggdesc_c)->dtagd_rec;

		/*
		 * We need to somehow perserve the aggergation name capability.
		 */
	}
	case DTRACEIOC_FORMAT_C: {
		dtrace_fmtdesc_t *fmt;
		dtrace_fmtdesc_c_t *fmt_c = (dtrace_fmtdesc_c_t *) data;

		error = 0;
		fmt = malloc(sizeof(dtrace_fmtdesc_t), M_DTRACEIOC, M_WAITOK);

		*t_datap = fmt;
		*t_comp = _IOC_NEWTYPE(com, dtrace_fmtdesc_t);

		CP((*fmt_c), (*fmt), dtfd_length);
		CP((*fmt_c), (*fmt), dtfd_format);

		error = cheriabi_cap_to_ptr((caddr_t *) &fmt->dtfd_string,
		    fmt_c->dtfd_string, fmt_c->dtfd_length, CHERI_PERM_STORE, 0);
	}
	case DTRACEIOC_DOFGET_C: {
		dof_hdr_t **hdr;
		dof_hdr_t **hdr_c = (dof_hdr_t **) data;
		int i;

		hdr = malloc(sizeof(dof_hdr_t *), M_DTRACEIOC, M_WAITOK);
		*hdr = malloc(sizeof(dof_hdr_t), M_DTRACEIOC, M_WAITOK);

		for (i = 0; i < DOF_ID_SIZE; i++)
			CP((**hdr_c), (**hdr), dofh_ident[i]);

		CP((**hdr_c), (**hdr), dofh_flags);
		CP((**hdr_c), (**hdr), dofh_hdrsize);
		CP((**hdr_c), (**hdr), dofh_secsize);
		CP((**hdr_c), (**hdr), dofh_secnum);
		CP((**hdr_c), (**hdr), dofh_secoff);
		CP((**hdr_c), (**hdr), dofh_loadsz);
		CP((**hdr_c), (**hdr), dofh_filesz);
		CP((**hdr_c), (**hdr), dofh_pad);
	}
	default:
		error = EINVAL;
	}

	return (error);
}

static int
cheriabi_dtrace_ioctl_translate_out(u_long com,
    void *data, void *t_data)
{

	return (EINVAL);
}

int
cheriabi_dtrace_in(u_long com, void *data, u_long *t_comp, void **t_datap)
{

	return (cheriabi_dtrace_ioctl_translate_in(com, data, t_comp, t_datap));
}

int
cheriabi_dtrace_out(u_long com, void *data, void *t_data)
{

	return (cheriabi_dtrace_ioctl_translate_out(com, data, t_data));
}

