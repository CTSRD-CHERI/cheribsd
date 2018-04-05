/*-
 * Copyright (c) 2008 David E. O'Brien
 * Copyright (c) 2015-2016 SRI International
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
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 * $FreeBSD$
 */

#ifndef _COMPAT_CHERIABI_IOCTL_H_
#define	_COMPAT_CHERIABI_IOCTL_H_

#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/rman.h>
#include <sys/bus_dma.h>
#include <sys/mdioctl.h>

#include <net/if.h>
#include <net/if_media.h>
#include <net/ifq.h>
#include <net/ethernet.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip_carp.h>
#include <net/if_gre.h>
#include <net/if_gif.h>
#include <net/pfvar.h>
#include <netpfil/pf/pf.h>
#include <net/if_pfsync.h>
#include <net/if_sppp.h>
#include <net/if_tap.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>

#include <security/mac/mac_framework.h>

#include <cam/scsi/scsi_sg.h>
#include <dev/ath/if_athioctl.h>
#include <dev/de/dc21040reg.h>
#include <dev/de/if_devar.h>
#include <dev/bxe/bxe.h>
#include <dev/iwi/if_iwireg.h>
#include <dev/iwi/if_iwi_ioctl.h>
#include <dev/mwl/mwlhal.h>
#include <dev/mwl/if_mwlioctl.h>
#include <dev/sbni/if_sbnireg.h>
#include <dev/sbni/if_sbnivar.h>

struct ioc_read_toc_entry_c {
	u_char	address_format;
	u_char	starting_track;
	u_short	data_len;
	void * __capability data;		/* struct cd_toc_entry* */
};
#define	CDIOREADTOCENTRYS_C \
    _IOC_NEWTYPE(CDIOREADTOCENTRYS, struct ioc_read_toc_entry_c)

struct fiodgname_arg_c {
	int		len;
	void * __capability	buf;
};
#define	FIODGNAME_C	_IOC_NEWTYPE(FIODGNAME, struct fiodgname_arg_c)

struct pci_conf_io_c {
	u_int32_t		pat_buf_len;	/* pattern buffer length */
	u_int32_t		num_patterns;	/* number of patterns */
	void * __capability		patterns;	/* struct pci_match_conf ptr */
	u_int32_t		match_buf_len;	/* match buffer length */
	u_int32_t		num_matches;	/* number of matches returned */
	void * __capability		matches;	/* struct pci_conf ptr */
	u_int32_t		offset;		/* offset into device list */
	u_int32_t		generation;	/* device list generation */
	u_int32_t		status;		/* request status */
};
#define	PCIOCGETCONF_C	_IOC_NEWTYPE(PCIOCGETCONF, struct pci_conf_io_c)

struct sg_io_hdr_c {
	int		interface_id;
	int		dxfer_direction;
	u_char		cmd_len;
	u_char		mx_sb_len;
	u_short		iovec_count;
	u_int		dxfer_len;
	void * __capability	dxferp;
	void * __capability	cmdp;
	void * __capability	sbp;
	u_int		timeout;
	u_int		flags;
	int		pack_id;
	void * __capability	usr_ptr;
	u_char		status;
	u_char		masked_status;
	u_char		msg_status;
	u_char		sb_len_wr;
	u_short		host_status;
	u_short		driver_status;
	int		resid;
	u_int		duration;
	u_int		info;
};
#define	SG_IO_C	_IOC_NEWTYPE(SG_IO, struct sg_io_hdr_c)

struct ifmediareq_c {
	char		ifm_name[IFNAMSIZ];
	int		ifm_current;
	int		ifm_mask;
	int		ifm_status;
	int		ifm_active;
	int		ifm_count;
	void * __capability	ifm_ulist;	/* int * */
};

#define	SIOCGIFMEDIA_C		_IOC_NEWTYPE(SIOCGIFMEDIA, struct ifmediareq_c)
#define	SIOCGIFXMEDIA_C		_IOC_NEWTYPE(SIOCGIFXMEDIA, struct ifmediareq_c)

#endif	/* _COMPAT_CHERIABI_IOCTL_H_ */
