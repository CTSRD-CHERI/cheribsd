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

struct bpf_program_c {
	u_int bf_len;
	void * __capability bf_insns;
};
#define BIOCSETF_C	_IOC_NEWTYPE(BIOCSETF, struct bpf_program_c)
#define BIOCSETWF_C	_IOC_NEWTYPE(BIOCSETWF, struct bpf_program_c)
#define BIOCSETFNR_C	_IOC_NEWTYPE(BIOCSETFNR, struct bpf_program_c)

/* ifr_data consumers */
#define	BXE_IOC_RD_NVRAM_C	_IOC_NEWTYPE(BXE_IOC_RD_NVRAM, struct ifreq_c)
#define	BXE_IOC_STATS_SHOW_C	_IOC_NEWTYPE(BXE_IOC_STATS_SHOW, struct ifreq_c)
#define	BXE_IOC_STATS_SHOW_CNT_C \
    _IOC_NEWTYPE(BXE_IOC_STATS_SHOW_CNT, struct ifreq_c)
#define	BXE_IOC_STATS_SHOW_NUM_C \
    _IOC_NEWTYPE(BXE_IOC_STATS_SHOW_NUM, struct ifreq_c)
#define	BXE_IOC_STATS_SHOW_STR_C \
    _IOC_NEWTYPE(BXE_IOC_STATS_SHOW_STR, struct ifreq_c)
#define	BXE_IOC_WR_NVRAM_C	_IOC_NEWTYPE(BXE_IOC_WR_NVRAM, struct ifreq_c)
#define	GIFGOPTS_C		_IOC_NEWTYPE(GIFGOPTS, struct ifreq_c)
#define	GIFSOPTS_C		_IOC_NEWTYPE(GIFSOPTS, struct ifreq_c)
#define	GREGKEY_C		_IOC_NEWTYPE(GREGKEY, struct ifreq_c)
#define	GREGOPTS_C		_IOC_NEWTYPE(GREGOPTS, struct ifreq_c)
#define	GRESKEY_C		_IOC_NEWTYPE(GRESKEY, struct ifreq_c)
#define	GRESOPTS_C		_IOC_NEWTYPE(GRESOPTS, struct ifreq_c)
#define	SIOCG80211STATS_C	_IOC_NEWTYPE(SIOCG80211STATS, struct ifreq_c)
#define	SIOCGATHAGSTATS_C	_IOC_NEWTYPE(SIOCGATHAGSTATS, struct ifreq_c)
#define	SIOCGETPFSYNC_C		_IOC_NEWTYPE(SIOCGETPFSYNC, struct ifreq_c)
#define	SIOCGETVLAN_C		_IOC_NEWTYPE(SIOCGETVLAN, struct ifreq_c)
#define	SIOCGI2C_C		_IOC_NEWTYPE(SIOCGI2C, struct ifreq_c)
#define	SIOCGI2C_C		_IOC_NEWTYPE(SIOCGI2C, struct ifreq_c)
#define	SIOCGI2C_C		_IOC_NEWTYPE(SIOCGI2C, struct ifreq_c)
#define	SIOCGIFGENERIC_C	_IOC_NEWTYPE(SIOCGIFGENERIC, struct ifreq_c)
#define	SIOCGIWISTATS_C		_IOC_NEWTYPE(SIOCGIWISTATS, struct ifreq_c)
#define	SIOCGVH_C		_IOC_NEWTYPE(SIOCGVH, struct ifreq_c)
#define	SIOCIFCREATE2_C		_IOC_NEWTYPE(SIOCIFCREATE2, struct ifreq_c)
#define	SIOCSETPFSYNC_C		_IOC_NEWTYPE(SIOCSETPFSYNC, struct ifreq_c)
#define	SIOCSETVLAN_C		_IOC_NEWTYPE(SIOCSETVLAN, struct ifreq_c)
#define	SIOCSIFGENERIC_C	_IOC_NEWTYPE(SIOCSIFGENERIC, struct ifreq_c)

/* XXX-BD: these confict */
#define	SIOCGATHSTATS_C		_IOC_NEWTYPE(SIOCGATHSTATS, struct ifreq_c)
#define	SIOCGMVSTATS_C		_IOC_NEWTYPE(SIOCGMVSTATS, struct ifreq_c)

static const struct {
	int	cmd;
	size_t	size;
	register_t	perms;
} cheriabi_ioctl_iru_data_consumers[] =
{
	{ BXE_IOC_RD_NVRAM_C, sizeof(struct bxe_nvram_data),
	    CHERI_PERM_STORE },
	{ BXE_IOC_WR_NVRAM_C, sizeof(struct bxe_nvram_data), CHERI_PERM_LOAD },
	{ BXE_IOC_STATS_SHOW_CNT_C, SIZE_MAX },	/* Internal, dissallow */
	{ BXE_IOC_STATS_SHOW_NUM_C, SIZE_MAX },	/* Internal, dissallow */
	{ BXE_IOC_STATS_SHOW_STR_C, SIZE_MAX },	/* Internal, dissallow */
	{ GIFGOPTS_C, sizeof(u_int), CHERI_PERM_STORE },
	{ GIFSOPTS_C, sizeof(u_int), CHERI_PERM_LOAD },
	{ GREGKEY_C, sizeof(uint32_t), CHERI_PERM_STORE },
	{ GREGOPTS_C, sizeof(uint32_t), CHERI_PERM_STORE },
	{ GRESKEY_C, sizeof(uint32_t), CHERI_PERM_LOAD },
	{ GRESOPTS_C, sizeof(uint32_t), CHERI_PERM_LOAD },
	{ SIOCG80211STATS_C, sizeof(struct ieee80211_stats),
	    CHERI_PERM_STORE },
	{ SIOCGATHAGSTATS_C, sizeof(struct ath_tx_aggr_stats),
	    CHERI_PERM_STORE },
	/* XXX-BD: conflicts with SIOCGMVSTATS_C, disabled */
	{ SIOCGATHSTATS_C, SIZE_MAX, CHERI_PERM_STORE },
	{ SIOCGETPFSYNC_C, sizeof(struct pfsyncreq), CHERI_PERM_STORE },
	{ SIOCGETVLAN_C, sizeof(struct vlanreq), CHERI_PERM_STORE },
	{ SIOCGI2C_C, sizeof(struct ifi2creq),
	    CHERI_PERM_LOAD | CHERI_PERM_STORE },
	/*
	 * XXX-BD: Also used in an(4) and wl(4) which I've marked broken
	 * for CPU_CHERI.
	 */
	{ SIOCGIFGENERIC_C, sizeof(struct spppreq),
	    CHERI_PERM_LOAD | CHERI_PERM_STORE },
	{ SIOCGIWISTATS_C, sizeof(struct iwi_notif_link_quality),
	    CHERI_PERM_STORE },
	{ SIOCGMVSTATS_C, sizeof(struct mwl_stats),
	    CHERI_PERM_STORE },
	/* Copies out at least one struct carpreq */
	{ SIOCGVH_C, sizeof(struct carpreq),
	    CHERI_PERM_LOAD | CHERI_PERM_STORE },
	/* Opaque data only used by wlan(4) in an RO capacity */
	/* XXX-BD: possible information leak */
	{ SIOCIFCREATE2_C, 0, CHERI_PERM_LOAD },
	{ SIOCSETPFSYNC_C, sizeof(struct pfsyncreq), CHERI_PERM_LOAD },
	{ SIOCSETVLAN_C, sizeof(struct vlanreq), CHERI_PERM_LOAD },
	/*
	 * XXX-BD: Also used in an(4) and wl(4) which I've marked broken
	 * for CPU_CHERI.
	 */
	{ SIOCSIFGENERIC_C, sizeof(struct spppreq), CHERI_PERM_LOAD },
	{ 0, SIZE_MAX }
};

/* Other ifreq users */
#define	BIOCGETIF_C		_IOC_NEWTYPE(BIOCGETIF, struct ifreq_c)
#define	BIOCSETIF_C		_IOC_NEWTYPE(BIOCSETIF, struct ifreq_c)
#define	GREGADDRD_C		_IOC_NEWTYPE(GREGADDRD, struct ifreq_c)
#define	GREGADDRS_C		_IOC_NEWTYPE(GREGADDRS, struct ifreq_c)
#define	GREGPROTO_C		_IOC_NEWTYPE(GREGPROTO, struct ifreq_c)
#define	GRESADDRD_C		_IOC_NEWTYPE(GRESADDRD, struct ifreq_c)
#define	GRESADDRS_C		_IOC_NEWTYPE(GRESADDRS, struct ifreq_c)
#define	GRESPROTO_C		_IOC_NEWTYPE(GRESPROTO, struct ifreq_c)
#define	SIOCADDMULTI_C		_IOC_NEWTYPE(SIOCADDMULTI, struct ifreq_c)
#define	SIOCDELMULTI_C		_IOC_NEWTYPE(SIOCDELMULTI, struct ifreq_c)
#define	SIOCDIFADDR_C		_IOC_NEWTYPE(SIOCDIFADDR, struct ifreq_c)
#define	SIOCDIFPHYADDR_C	_IOC_NEWTYPE(SIOCDIFPHYADDR, struct ifreq_c)
#define	SIOCGETVLAN_C		_IOC_NEWTYPE(SIOCGETVLAN, struct ifreq_c)
#define	SIOCGHWFLAGS_C		_IOC_NEWTYPE(SIOCGHWFLAGS, struct ifreq_c)
#define	SIOCGIFBRDADDR_C	_IOC_NEWTYPE(SIOCGIFBRDADDR, struct ifreq_c)
#define	SIOCGIFCAP_C		_IOC_NEWTYPE(SIOCGIFCAP, struct ifreq_c)
#define	SIOCGIFDSTADDR_C	_IOC_NEWTYPE(SIOCGIFDSTADDR, struct ifreq_c)
#define	SIOCGIFFIB_C		_IOC_NEWTYPE(SIOCGIFFIB, struct ifreq_c)
#define	SIOCGIFFLAGS_C		_IOC_NEWTYPE(SIOCGIFFLAGS, struct ifreq_c)
#define	SIOCGIFINDEX_C		_IOC_NEWTYPE(SIOCGIFINDEX, struct ifreq_c)
#define	SIOCGIFMETRIC_C		_IOC_NEWTYPE(SIOCGIFMETRIC, struct ifreq_c)
#define	SIOCGIFMTU_C		_IOC_NEWTYPE(SIOCGIFMTU, struct ifreq_c)
#define	SIOCGIFNETMASK_C	_IOC_NEWTYPE(SIOCGIFNETMASK, struct ifreq_c)
#define	SIOCGIFPDSTADDR_C	_IOC_NEWTYPE(SIOCGIFPDSTADDR, struct ifreq_c)
#define	SIOCGIFPHYS_C		_IOC_NEWTYPE(SIOCGIFPHYS, struct ifreq_c)
#define	SIOCGIFPSRCADDR_C	_IOC_NEWTYPE(SIOCGIFPSRCADDR, struct ifreq_c)
#define	SIOCGINSTATS_C		_IOC_NEWTYPE(SIOCGINSTATS, struct ifreq_c)
#define	SIOCGPRISM2DEBUG_C	_IOC_NEWTYPE(SIOCGPRISM2DEBUG, struct ifreq_c)
#define	SIOCGPRIVATE_0_C	_IOC_NEWTYPE(SIOCGPRIVATE_0, struct ifreq_c)
#define	SIOCGPRIVATE_1_C	_IOC_NEWTYPE(SIOCGPRIVATE_1, struct ifreq_c)
#define	SIOCGTUNFIB_C		_IOC_NEWTYPE(SIOCGTUNFIB, struct ifreq_c)
#define	SIOCGWLCACHE_C		_IOC_NEWTYPE(SIOCGWLCACHE, struct ifreq_c)
#define	SIOCGWLCITEM_C		_IOC_NEWTYPE(SIOCGWLCITEM, struct ifreq_c)
#define	SIOCGWLCNWID_C		_IOC_NEWTYPE(SIOCGWLCNWID, struct ifreq_c)
#define	SIOCGWLEEPROM_C		_IOC_NEWTYPE(SIOCGWLEEPROM, struct ifreq_c)
#define	SIOCGWLPSA_C		_IOC_NEWTYPE(SIOCGWLPSA, struct ifreq_c)
#define	SIOCIFCREATE_C		_IOC_NEWTYPE(SIOCIFCREATE, struct ifreq_c)
#define	SIOCIFDESTROY_C		_IOC_NEWTYPE(SIOCIFDESTROY, struct ifreq_c)
#define	SIOCRINSTATS_C		_IOC_NEWTYPE(SIOCRINSTATS, struct ifreq_c)
#define	SIOCSETVLAN_C		_IOC_NEWTYPE(SIOCSETVLAN, struct ifreq_c)
#define	SIOCSIFADDR_C		_IOC_NEWTYPE(SIOCSIFADDR, struct ifreq_c)
#define	SIOCSIFBRDADDR_C	_IOC_NEWTYPE(SIOCSIFBRDADDR, struct ifreq_c)
#define	SIOCSIFCAP_C		_IOC_NEWTYPE(SIOCSIFCAP, struct ifreq_c)
#define	SIOCSIFDSTADDR_C	_IOC_NEWTYPE(SIOCSIFDSTADDR, struct ifreq_c)
#define	SIOCSIFFIB_C		_IOC_NEWTYPE(SIOCSIFFIB, struct ifreq_c)
#define	SIOCSIFFLAGS_C		_IOC_NEWTYPE(SIOCSIFFLAGS, struct ifreq_c)
#define	SIOCSIFLLADDR_C		_IOC_NEWTYPE(SIOCSIFLLADDR, struct ifreq_c)
#define	SIOCSIFMEDIA_C		_IOC_NEWTYPE(SIOCSIFMEDIA, struct ifreq_c)
#define	SIOCSIFMETRIC_C		_IOC_NEWTYPE(SIOCSIFMETRIC, struct ifreq_c)
#define	SIOCSIFMTU_C		_IOC_NEWTYPE(SIOCSIFMTU, struct ifreq_c)
#define	SIOCSIFNETMASK_C	_IOC_NEWTYPE(SIOCSIFNETMASK, struct ifreq_c)
#define	SIOCSIFPHYS_C		_IOC_NEWTYPE(SIOCSIFPHYS, struct ifreq_c)
#define	SIOCSIFRVNET_C		_IOC_NEWTYPE(SIOCSIFRVNET, struct ifreq_c)
#define	SIOCSIFVNET_C		_IOC_NEWTYPE(SIOCSIFVNET, struct ifreq_c)
#define	SIOCSPRISM2DEBUG_C	_IOC_NEWTYPE(SIOCSPRISM2DEBUG, struct ifreq_c)
#define	SIOCSTUNFIB_C		_IOC_NEWTYPE(SIOCSTUNFIB, struct ifreq_c)
#define	SIOCSVH_C		_IOC_NEWTYPE(SIOCSVH, struct ifreq_c)
#define	SIOCSWLCNWID_C		_IOC_NEWTYPE(SIOCSWLCNWID, struct ifreq_c)
#define	SIOCSWLPSA_C		_IOC_NEWTYPE(SIOCSWLPSA, struct ifreq_c)
#define	SIOCSWLTHR_C		_IOC_NEWTYPE(SIOCSWLTHR, struct ifreq_c)
#define	SIOCZATHSTATS_C		_IOC_NEWTYPE(SIOCZATHSTATS, struct ifreq_c)
#define	SIOCZIWISTATS_C		_IOC_NEWTYPE(SIOCZIWISTATS, struct ifreq_c)
#define	TAPGIFNAME_C		_IOC_NEWTYPE(TAPGIFNAME, struct ifreq_c)

int	ioctl_data_contains_pointers(u_long cmd);

struct ifgroupreq_c {
	char	ifgr_name[IFNAMSIZ];
	u_int	ifgr_len;
	union {
		char	ifgru_group[IFNAMSIZ];
		void * __capability	ifgru_groups;	/* struct ifg_req * */
	} ifgr_ifgru;
};

#define	SIOCAIFGROUP_C		_IOC_NEWTYPE(SIOCAIFGROUP, struct ifgroupreq_c)
#define	SIOCGIFGROUP_C		_IOC_NEWTYPE(SIOCGIFGROUP, struct ifgroupreq_c)
#define	SIOCDIFGROUP_C		_IOC_NEWTYPE(SIOCDIFGROUP, struct ifgroupreq_c)
#define	SIOCGIFGMEMB_C		_IOC_NEWTYPE(SIOCGIFGMEMB, struct ifgroupreq_c)

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
