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

#include <cheri/cheri.h>
#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_ioctl.h>
#include <compat/cheriabi/cheriabi_dtrace.h>

MALLOC_DECLARE(M_DTRACEIOC);
MALLOC_DEFINE(M_DTRACEIOC, "dtraceioc", "DTrace CheriABI ioctl");

static int
cheriabi_dtrace_ioctl_translate_in(u_long com,
    void *data, u_long *t_comp, void **t_datap)
{
	int error;

	error = 0;

	switch (com) {
	case DTRACEIOC_AGGSNAP_C:
	case DTRACEIOC_BUFSNAP_C: {
		/*
		 * We have to ensure that *pdesc and pdesc is freed on the out
		 * path.
		 */
		dtrace_bufdesc_t **pdesc;
		dtrace_bufdesc_c_t **pdesc_c = data;

		error = 0;
		pdesc = malloc(sizeof(dtrace_bufdesc_t *), M_DTRACEIOC, M_WAITOK);
		*pdesc = malloc(sizeof(dtrace_bufdesc_t), M_DTRACEIOC, M_WAITOK | M_ZERO);

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
		break;
	}
	case DTRACEIOC_ENABLE_C: {
		/*
		 * The problem with this is that we have the data in userspace
		 * inside the DOF that corresponds to purecap. In the hybrid
		 * ABI, we have an issue with the alignment being different, as
		 * well as the size of various things in the DOF being
		 * different. For DTrace, we really need to proivde a way to
		 * convert this from purecap to non-CHERI.
		 */
		dtrace_enable_io_t *p;
		dtrace_enable_io_c_t *p_c = data;

		error = 0;
		p = malloc(sizeof(dtrace_enable_io_t), M_DTRACEIOC, M_WAITOK | M_ZERO);

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
		p->dof = (void *) p_c->dof;
		break;
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
		 * without being invasive in DTrace itself (which we probably
		 * don't want too much...).
		 */
		size_t i;
		dtrace_aggdesc_t **paggdesc;
		dtrace_aggdesc_c_t **paggdesc_c = data;

		error = 0;
		paggdesc = malloc(sizeof(dtrace_aggdesc_c_t *), M_DTRACEIOC, M_WAITOK);
		*paggdesc = malloc(sizeof(dtrace_aggdesc_t), M_DTRACEIOC, M_WAITOK | M_ZERO);

		*t_datap = paggdesc;
		*t_comp = _IOC_NEWTYPE(com, dtrace_aggdesc_t *);

		CP((**paggdesc_c), (**paggdesc), dtagd_varid);
		CP((**paggdesc_c), (**paggdesc), dtagd_flags);
		CP((**paggdesc_c), (**paggdesc), dtagd_id);
		CP((**paggdesc_c), (**paggdesc), dtagd_epid);
		CP((**paggdesc_c), (**paggdesc), dtagd_size);
		CP((**paggdesc_c), (**paggdesc), dtagd_nrecs);
		CP((**paggdesc_c), (**paggdesc), dtagd_pad);

		for (i = 0; i < (*paggdesc_c)->dtagd_nrecs; i++)
			CP((**paggdesc_c), ((**paggdesc)), dtagd_rec[i]);

		/*
		 * We need to somehow perserve the aggergation name capability.
		 * For now, just do a CGetOffset through a cast.
		 */

		error = cheriabi_strcap_to_ptr(&(*paggdesc)->dtagd_name,
		    (*paggdesc_c)->dtagd_name, 1);
		break;
	}
	case DTRACEIOC_FORMAT_C: {
		dtrace_fmtdesc_t *fmt;
		dtrace_fmtdesc_c_t *fmt_c = data;

		error = 0;
		fmt = malloc(sizeof(dtrace_fmtdesc_t), M_DTRACEIOC, M_WAITOK | M_ZERO);

		*t_datap = fmt;
		*t_comp = _IOC_NEWTYPE(com, dtrace_fmtdesc_t);

		CP((*fmt_c), (*fmt), dtfd_length);
		CP((*fmt_c), (*fmt), dtfd_format);

		error = cheriabi_cap_to_ptr((caddr_t *) &fmt->dtfd_string,
		    fmt_c->dtfd_string, fmt_c->dtfd_length, CHERI_PERM_STORE, 1);
		break;
	}
	case DTRACEIOC_DOFGET_C: {
		dof_hdr_t **hdr;
		dof_hdr_t **hdr_c = data;
		int i;

		error = 0;
		hdr = malloc(sizeof(dof_hdr_t *), M_DTRACEIOC, M_WAITOK);
		*hdr = malloc(sizeof(dof_hdr_t), M_DTRACEIOC, M_WAITOK | M_ZERO);

		*t_datap = hdr;
		*t_comp = _IOC_NEWTYPE(com, dof_hdr_t *);

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
		break;
	}
	case DTRACEIOC_EPROBE_C: {
		size_t i;
		dtrace_eprobedesc_t **epdesc;
		dtrace_eprobedesc_c_t **epdesc_c = data;

		error = 0;
		epdesc = malloc(sizeof(dtrace_eprobedesc_t *), M_DTRACEIOC, M_WAITOK);
		*epdesc = malloc(sizeof(dtrace_eprobedesc_t), M_DTRACEIOC, M_WAITOK | M_ZERO);

		*t_datap = epdesc;
		*t_comp = _IOC_NEWTYPE(com, dtrace_eprobedesc_t *);

		CP((**epdesc_c), (**epdesc), dtepd_epid);
		CP((**epdesc_c), (**epdesc), dtepd_probeid);
		CP((**epdesc_c), (**epdesc), dtepd_size);
		CP((**epdesc_c), (**epdesc), dtepd_nrecs);

		for (i = 0; i < (*epdesc)->dtepd_nrecs; i++)
			CP((**epdesc_c), (**epdesc), dtepd_rec[i]);
		break;
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
	int error;

	switch (com) {
	case DTRACEIOC_AGGSNAP_C:
	case DTRACEIOC_BUFSNAP_C: {
		size_t i;
		dtrace_bufdesc_t **pdesc = t_data;
		dtrace_bufdesc_c_t **pdesc_c = data;

		error = 0;
		CP((**pdesc), (**pdesc_c), dtbd_size);
		CP((**pdesc), (**pdesc_c), dtbd_cpu);
		CP((**pdesc), (**pdesc_c), dtbd_errors);
		CP((**pdesc), (**pdesc_c), dtbd_drops);
		CP((**pdesc), (**pdesc_c), dtbd_oldest);
		CP((**pdesc), (**pdesc_c), dtbd_timestamp);

		for (i = 0; i < (*pdesc_c)->dtbd_size; i++)
			CP((**pdesc), (**pdesc_c), dtbd_data[i]);

		free(*pdesc_c, M_DTRACEIOC);
		break;
	}
	case DTRACEIOC_AGGDESC_C: {
		size_t i;
		dtrace_aggdesc_t **paggdesc = t_data;
		dtrace_aggdesc_c_t **paggdesc_c = data;

		error = 0;

		CP((**paggdesc), (**paggdesc_c), dtagd_id);
		CP((**paggdesc), (**paggdesc_c), dtagd_epid);
		CP((**paggdesc), (**paggdesc_c), dtagd_size);
		CP((**paggdesc), (**paggdesc_c), dtagd_nrecs);
		CP((**paggdesc), (**paggdesc_c), dtagd_pad);

		for (i = 0; i < (*paggdesc)->dtagd_nrecs; i++)
			CP((**paggdesc), (**paggdesc_c), dtagd_rec[i]);

		free(*paggdesc_c, M_DTRACEIOC);
		break;
	}
	case DTRACEIOC_FORMAT_C: {
		size_t i;
		dtrace_fmtdesc_t *fmt = t_data;
		dtrace_fmtdesc_c_t *fmt_c = data;

		error = 0;

		CP((*fmt), (*fmt_c), dtfd_length);
		CP((*fmt), (*fmt_c), dtfd_format);

		for (i = 0; i < fmt_c->dtfd_length; i++)
			CP((*fmt), (*fmt_c), dtfd_string[i]);
		break;
	}
	case DTRACEIOC_DOFGET_C: {
		size_t i;
		dof_hdr_t **hdr = t_data;
		dof_hdr_t **hdr_c = data;

		CP((**hdr), (**hdr_c), dofh_flags);
		CP((**hdr), (**hdr_c), dofh_hdrsize);
		CP((**hdr), (**hdr_c), dofh_secsize);
		CP((**hdr), (**hdr_c), dofh_secnum);
		CP((**hdr), (**hdr_c), dofh_secoff);
		CP((**hdr), (**hdr_c), dofh_loadsz);
		CP((**hdr), (**hdr_c), dofh_filesz);
		CP((**hdr), (**hdr_c), dofh_pad);

		for (i = 0; i < DOF_ID_SIZE; i++)
			CP((**hdr), (**hdr_c), dofh_ident[i]);
		break;
	}
	case DTRACEIOC_EPROBE_C: {
		size_t i;
		dtrace_eprobedesc_t **epdesc = t_data;
		dtrace_eprobedesc_c_t **epdesc_c = data;

		CP((**epdesc), (**epdesc_c), dtepd_epid);
		CP((**epdesc), (**epdesc_c), dtepd_probeid);
		CP((**epdesc), (**epdesc_c), dtepd_size);
		CP((**epdesc), (**epdesc_c), dtepd_nrecs);

		for (i = 0; i < (*epdesc)->dtepd_nrecs; i++)
			CP((**epdesc), (**epdesc_c), dtepd_rec[i]);
		break;
	}
	default:
		error = EINVAL;
	}

	error = 0;

	return (error);
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

