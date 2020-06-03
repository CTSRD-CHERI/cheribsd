/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * $FreeBSD$
 *
 */

static void * __capability
dtrace_make_buffdesc_cap(caddr_t addr)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI))
	    return (__USER_CAP_OBJ(*(dtrace_bufdesc64_t **)addr));
#endif
	return (*(dtrace_bufdesc_t * __capability *)addr);
}

static int
dtrace_copyin_buffdesc(dtrace_bufdesc_t * __capability uaddr,
    dtrace_bufdesc_t *bufdesc)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_bufdesc64_t bufdesc64;
		int error = copyin(uaddr, &bufdesc64, sizeof (bufdesc64));
		if (error != 0)
			return (error);
		bufdesc->dtbd_size = bufdesc64.dtbd_size;
		bufdesc->dtbd_cpu = bufdesc64.dtbd_cpu;
		bufdesc->dtbd_errors = bufdesc64.dtbd_errors;
		bufdesc->dtbd_drops = bufdesc64.dtbd_drops;
		bufdesc->dtbd_data = __USER_CAP_STR(bufdesc64.dtbd_data);
		bufdesc->dtbd_oldest = bufdesc64.dtbd_oldest;
		bufdesc->dtbd_timestamp = bufdesc64.dtbd_timestamp;
		return (0);
	}
#endif
	return (copyincap(uaddr, bufdesc, sizeof (dtrace_bufdesc_t)));
}

static int
dtrace_copyout_buffdesc(dtrace_bufdesc_t *bufdesc,
    dtrace_bufdesc_t * __capability uaddr)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_bufdesc64_t bufdesc64;
		bufdesc64.dtbd_size = bufdesc->dtbd_size;
		bufdesc64.dtbd_cpu = bufdesc->dtbd_cpu;
		bufdesc64.dtbd_errors = bufdesc->dtbd_errors;
		bufdesc64.dtbd_drops = bufdesc->dtbd_drops;
		bufdesc64.dtbd_data = (__cheri_addr uint64_t)bufdesc->dtbd_data;
		bufdesc64.dtbd_oldest = bufdesc->dtbd_oldest;
		bufdesc64.dtbd_timestamp = bufdesc->dtbd_timestamp;
		return (copyout(&bufdesc64, uaddr, sizeof(dtrace_bufdesc64_t)));
	}
#endif
	return (copyoutcap(bufdesc, uaddr, sizeof (dtrace_bufdesc_t)));
}

static void
dtrace_copy_recdesc(const dtrace_recdesc_t *recdesc, void *dest)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_recdesc64_t recdesc64;
		recdesc64.dtrd_action = recdesc->dtrd_action;
		recdesc64.dtrd_size = recdesc->dtrd_size;
		recdesc64.dtrd_offset = recdesc->dtrd_offset;
		recdesc64.dtrd_alignment = recdesc->dtrd_alignment;
		recdesc64.dtrd_format = recdesc->dtrd_format;
		recdesc64.dtrd_arg = recdesc->dtrd_arg;
		recdesc64.dtrd_uarg = (__cheri_addr uint64_t)recdesc->dtrd_uarg;
		bcopy(&recdesc64, dest, sizeof (dtrace_recdesc64_t));
		return;
	}
#endif
	bcopy(recdesc, dest, sizeof (dtrace_recdesc_t));
}

static void
dtrace_copy_aggdesc(const dtrace_aggdesc_t *aggdesc, void *dest)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_aggdesc64_t aggdesc64;
		aggdesc64.tagd_name =
		    (__cheri_addr uint64_t)aggdesc->dtagd_name;
		aggdesc64.dtagd_varid = aggdesc->dtagd_varid;
		aggdesc64.dtagd_flags = aggdesc->dtagd_flags;
		aggdesc64.dtagd_id = aggdesc->dtagd_id;
		aggdesc64.dtagd_epid = aggdesc->dtagd_epid;
		aggdesc64.dtagd_size = aggdesc->dtagd_size;
		aggdesc64.dtagd_nrecs = aggdesc->dtagd_nrecs;
		aggdesc64.dtagd_pad = aggdesc->dtagd_pad;
		bcopy(&aggdesc64, dest, sizeof (dtrace_aggdesc64_t));
		return;
	}
#endif
	bcopy(aggdesc, dest, sizeof (dtrace_aggdesc_t));
}

static void * __capability
dtrace_make_aggdesc_cap(caddr_t addr)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI))
		return (__USER_CAP_OBJ(*(dtrace_aggdesc64_t **)addr));
#endif
	return (*(dtrace_aggdesc_t * __capability *)addr);
}

static int
dtrace_copyin_aggdesc(void * __capability uaddr, dtrace_aggdesc_t *aggdesc)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_aggdesc64_t aggdesc64;
		int error = copyin(uaddr, &aggdesc64, sizeof (aggdesc64));
		if (error != 0)
			return (error);
		aggdesc->dtagd_name =
		    __USER_CAP_STR((void *)aggdesc64.tagd_name);
		aggdesc->dtagd_varid = aggdesc64.dtagd_varid;
		aggdesc->dtagd_flags = aggdesc64.dtagd_flags;
		aggdesc->dtagd_id = aggdesc64.dtagd_id;
		aggdesc->dtagd_epid = aggdesc64.dtagd_epid;
		aggdesc->dtagd_size = aggdesc64.dtagd_size;
		aggdesc->dtagd_nrecs = aggdesc64.dtagd_nrecs;
		aggdesc->dtagd_pad = aggdesc64.dtagd_pad;
		return (0);
	}
#endif
	return (copyincap(uaddr, aggdesc, sizeof (dtrace_bufdesc_t)));
}

static u_long
dtrace_translate_ioctl_to_native(u_long cmd)
{

#define CASE(VAL)     \
	case VAL##64: \
		return (VAL)

#ifdef COMPAT_FREEBSD64
	switch (cmd) {
		CASE(DTRACEIOC_AGGDESC);
		CASE(DTRACEIOC_AGGSNAP);
		CASE(DTRACEIOC_BUFSNAP);
		CASE(DTRACEIOC_DOFGET);
		CASE(DTRACEIOC_ENABLE);
		CASE(DTRACEIOC_EPROBE);
		CASE(DTRACEIOC_FORMAT);
	}
#endif
#undef CASE

	return (cmd);
}

static dof_hdr_t * __capability
dtrace_make_pdof_cap(caddr_t addr)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		return (__USER_CAP_OBJ(*(dof_hdr_t **)addr));
	}
#endif
	return (*(dof_hdr_t * __capability *)addr);
}

static dtrace_enable_io_t
dtrace_make_enable_io(caddr_t addr)
{
#ifdef COMPAT_FREEBSD64
	dtrace_enable_io_t enable;

	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_enable_io64_t *p64 = (dtrace_enable_io64_t *)addr;
		enable.dof = __USER_CAP_UNBOUND((void *)p64->dof);
		enable.n_matched = p64->n_matched;
		return (enable);
	}
#endif
	return (*(dtrace_enable_io_t *)addr);
}

static void
dtrace_copy_enable_io(const dtrace_enable_io_t *from, caddr_t to)
{
#ifdef COMPAT_FREEBSD64
	dtrace_enable_io_t enable;

	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_enable_io64_t p64;
		p64.dof = (__cheri_addr uint64_t)from->dof;
		p64.n_matched = from->n_matched;
		bcopy(&p64, (void *)to, sizeof (dtrace_enable_io64_t));
		return;
	}
#endif
	bcopy(from, (void *)to, sizeof (dtrace_enable_io_t));
}

static void * __capability
dtrace_make_eprobedesc_cap(caddr_t addr)
{
#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		return (__USER_CAP_OBJ(*(dtrace_eprobedesc64_t **)addr));
	}
#endif
	return (*(dtrace_eprobedesc_t * __capability *)addr);
}

static dtrace_fmtdesc_t
dtrace_make_fmtdesc(caddr_t addr)
{
#ifdef COMPAT_FREEBSD64
	dtrace_fmtdesc_t desc;
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_fmtdesc64_t *p64 = (dtrace_fmtdesc64_t *)addr;
		desc.dtfd_string = __USER_CAP_STR(p64->dtfd_string);
		desc.dtfd_length = p64->dtfd_length;
		desc.dtfd_format = p64->dtfd_format;
		return (desc);
	}
#endif
	return (*(dtrace_fmtdesc_t *)addr);
}

static void
dtrace_copy_fmtdesc(const dtrace_fmtdesc_t *fmtdesc, caddr_t to)
{
#ifdef COMPAT_FREEBSD64
	dtrace_fmtdesc_t desc;
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		dtrace_fmtdesc64_t fmt64;
		fmt64.dtfd_string = (__cheri_addr uint64_t)fmtdesc->dtfd_string;
		fmt64.dtfd_length = fmtdesc->dtfd_length;
		fmt64.dtfd_format = fmtdesc->dtfd_format;
		bcopy(&fmt64, (void *)to, sizeof (dtrace_fmtdesc64_t));
		return;
	}
#endif
	bcopy(fmtdesc, (void *)to, sizeof (dtrace_fmtdesc_t));
}
