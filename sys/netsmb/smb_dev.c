/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/capsicum.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/file.h>		/* Must come after sys/malloc.h */
#include <sys/filedesc.h>
#include <sys/mbuf.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <net/if.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>

static struct cdev *nsmb_dev;

static d_open_t	 nsmb_dev_open;
static d_ioctl_t nsmb_dev_ioctl;

MODULE_DEPEND(netsmb, libiconv, 1, 1, 2);
MODULE_VERSION(netsmb, NSMB_VERSION);

static int smb_version = NSMB_VERSION;
struct sx smb_lock;

SYSCTL_DECL(_net_smb);
SYSCTL_INT(_net_smb, OID_AUTO, version, CTLFLAG_RD, &smb_version, 0, "");

static MALLOC_DEFINE(M_NSMBDEV, "NETSMBDEV", "NET/SMB device");

#ifdef COMPAT_FREEBSD32
struct smbioc_ossn32 {
	int		ioc_opt;
	uint32_t	ioc_svlen;	/* size of ioc_server address */
	uint32_t	ioc_server;	/* struct sockaddr * */
	uint32_t	ioc_lolen;	/* size of ioc_local address */
	uint32_t	ioc_local;	/* struct sockaddr * */
	char		ioc_srvname[SMB_MAXSRVNAMELEN + 1];
	int		ioc_timeout;
	int		ioc_retrycount;	/* number of retries before giveup */
	char		ioc_localcs[16];/* local charset */
	char		ioc_servercs[16];/* server charset */
	char		ioc_user[SMB_MAXUSERNAMELEN + 1];
	char		ioc_workgroup[SMB_MAXUSERNAMELEN + 1];
	char		ioc_password[SMB_MAXPASSWORDLEN + 1];
	uid_t		ioc_owner;	/* proposed owner */
	gid_t		ioc_group;	/* proposed group */
	mode_t		ioc_mode;	/* desired access mode */
	mode_t		ioc_rights;	/* SMBM_* */
};

struct smbioc_rq32 {
	u_char		ioc_cmd;
	u_char		ioc_twc;
	uint32_t	ioc_twords;	/* void * */
	u_short		ioc_tbc;
	uint32_t	ioc_tbytes;	/* void * */
	int		ioc_rpbufsz;
	uint32_t	ioc_rpbuf;	/* char * */
	u_char		ioc_rwc;
	u_short		ioc_rbc;
	u_int8_t	ioc_errclass;
	u_int16_t	ioc_serror;
	u_int32_t	ioc_error;
};

struct smbioc_t2rq32 {
	u_int16_t	ioc_setup[3];
	int		ioc_setupcnt;
	uint32_t	ioc_name;	/* char * */
	u_short		ioc_tparamcnt;
	uint32_t	ioc_tparam;	/* void * */
	u_short		ioc_tdatacnt;
	uint32_t	ioc_tdata;	/* void * */
	u_short		ioc_rparamcnt;
	uint32_t	ioc_rparam;	/* void * */
	u_short		ioc_rdatacnt;
	uint32_t	ioc_rdata;	/* void * */
};

struct smbioc_lookup32 {
	int		ioc_level;
	int		ioc_flags;
	struct smbioc_ossn32	ioc_ssn;
	struct smbioc_oshare	ioc_sh;
};

struct smbioc_rw32 {
	smbfh		ioc_fh;
	uint32_t	ioc_base;	/* char * */
	off_t		ioc_offset;
	int		ioc_cnt;
};

/*
 * Device IOCTLs
 */
#define	SMBIOC_OPENSESSION32	\
    _IOC_NEWTYPE(SMBIOC_OPENSESSION, struct smbioc_ossn32)
#define	SMBIOC_REQUEST32	_IOC_NEWTYPE(SMBIOC_REQUEST, struct smbioc_rq32)
#define	SMBIOC_T2RQ32		_IOC_NEWTYPE(SMBIOC_T2RQ, struct smbioc_t2rq32)
#define	SMBIOC_LOOKUP32			\
    _IOC_NEWTYPE(SMBIOC_LOOKUP, struct smbioc_lookup32)
#define	SMBIOC_READ32		_IOC_NEWTYPE(SMBIOC_READ, struct smbioc_rw32)
#define	SMBIOC_WRITE32		_IOC_NEWTYPE(SMBIOC_WRITE, struct smbioc_rw32)
#endif /* COMPAT_FREEBSD32 */

#ifdef COMPAT_FREEBSD64
struct smbioc_ossn64 {
	int		ioc_opt;
	uint32_t	ioc_svlen;	/* size of ioc_server address */
	uint64_t	ioc_server;	/* struct sockaddr * */
	uint32_t	ioc_lolen;	/* size of ioc_local address */
	uint64_t	ioc_local;	/* struct sockaddr * */
	char		ioc_srvname[SMB_MAXSRVNAMELEN + 1];
	int		ioc_timeout;
	int		ioc_retrycount;	/* number of retries before giveup */
	char		ioc_localcs[16];/* local charset */
	char		ioc_servercs[16];/* server charset */
	char		ioc_user[SMB_MAXUSERNAMELEN + 1];
	char		ioc_workgroup[SMB_MAXUSERNAMELEN + 1];
	char		ioc_password[SMB_MAXPASSWORDLEN + 1];
	uid_t		ioc_owner;	/* proposed owner */
	gid_t		ioc_group;	/* proposed group */
	mode_t		ioc_mode;	/* desired access mode */
	mode_t		ioc_rights;	/* SMBM_* */
};

struct smbioc_rq64 {
	u_char		ioc_cmd;
	u_char		ioc_twc;
	uint64_t	ioc_twords;	/* void * */
	u_short		ioc_tbc;
	uint64_t	ioc_tbytes;	/* void * */
	int		ioc_rpbufsz;
	uint64_t	ioc_rpbuf;	/* char * */
	u_char		ioc_rwc;
	u_short		ioc_rbc;
	u_int8_t	ioc_errclass;
	u_int16_t	ioc_serror;
	u_int32_t	ioc_error;
};

struct smbioc_t2rq64 {
	u_int16_t	ioc_setup[3];
	int		ioc_setupcnt;
	uint64_t	ioc_name;	/* char * */
	u_short		ioc_tparamcnt;
	uint64_t	ioc_tparam;	/* void * */
	u_short		ioc_tdatacnt;
	uint64_t	ioc_tdata;	/* void * */
	u_short		ioc_rparamcnt;
	uint64_t	ioc_rparam;	/* void * */
	u_short		ioc_rdatacnt;
	uint64_t	ioc_rdata;	/* void * */
};

struct smbioc_lookup64 {
	int		ioc_level;
	int		ioc_flags;
	struct smbioc_ossn64	ioc_ssn;
	struct smbioc_oshare	ioc_sh;
};

struct smbioc_rw64 {
	smbfh		ioc_fh;
	uint64_t	ioc_base;	/* char * */
	off_t		ioc_offset;
	int		ioc_cnt;
};

/*
 * Device IOCTLs
 */
#define	SMBIOC_OPENSESSION64	\
    _IOC_NEWTYPE(SMBIOC_OPENSESSION, struct smbioc_ossn64)
#define	SMBIOC_REQUEST64	_IOC_NEWTYPE(SMBIOC_REQUEST, struct smbioc_rq64)
#define	SMBIOC_T2RQ64		_IOC_NEWTYPE(SMBIOC_T2RQ, struct smbioc_t2rq64)
#define	SMBIOC_LOOKUP64			\
    _IOC_NEWTYPE(SMBIOC_LOOKUP, struct smbioc_lookup64)
#define	SMBIOC_READ64		_IOC_NEWTYPE(SMBIOC_READ, struct smbioc_rw64)
#define	SMBIOC_WRITE64		_IOC_NEWTYPE(SMBIOC_WRITE, struct smbioc_rw64)
#endif /* COMPAT_FREEBSD64 */

static struct cdevsw nsmb_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	nsmb_dev_open,
	.d_ioctl =	nsmb_dev_ioctl,
	.d_name =	NSMB_NAME
};

static int
nsmb_dev_init(void)
{

	nsmb_dev = make_dev(&nsmb_cdevsw, 0, UID_ROOT, GID_OPERATOR,
	    0600, "nsmb");
	if (nsmb_dev == NULL)
		return (ENOMEM);  
	return (0);
}

static void 
nsmb_dev_destroy(void)
{

	MPASS(nsmb_dev != NULL);
	destroy_dev(nsmb_dev);
	nsmb_dev = NULL;
}

static struct smb_dev *
smbdev_alloc(struct cdev *dev)
{
	struct smb_dev *sdp;

	sdp = malloc(sizeof(struct smb_dev), M_NSMBDEV, M_WAITOK | M_ZERO);
	sdp->dev = dev;	
	sdp->sd_level = -1;
	sdp->sd_flags |= NSMBFL_OPEN;
	sdp->refcount = 1;
	return (sdp);	
} 

void
sdp_dtor(void *arg)
{
	struct smb_dev *dev;

	dev = (struct smb_dev *)arg;	
	SMB_LOCK();
	sdp_trydestroy(dev);
	SMB_UNLOCK();
}

static int
nsmb_dev_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct smb_dev *sdp;
	int error;

	sdp = smbdev_alloc(dev);
	error = devfs_set_cdevpriv(sdp, sdp_dtor);
	if (error) {
		free(sdp, M_NSMBDEV);	
		return (error);
	}
	return (0);
}

void
sdp_trydestroy(struct smb_dev *sdp)
{
	struct smb_vc *vcp;
	struct smb_share *ssp;
	struct smb_cred *scred;

	SMB_LOCKASSERT();
	if (!sdp)
		panic("No smb_dev upon device close");
	MPASS(sdp->refcount > 0);
	sdp->refcount--;
	if (sdp->refcount) 
		return;
	scred = malloc(sizeof(struct smb_cred), M_NSMBDEV, M_WAITOK);
	smb_makescred(scred, curthread, NULL);
	ssp = sdp->sd_share;
	if (ssp != NULL) {
		smb_share_lock(ssp);
		smb_share_rele(ssp, scred);
	}
	vcp = sdp->sd_vc;
	if (vcp != NULL) {
		smb_vc_lock(vcp);
		smb_vc_rele(vcp, scred);
	}
	free(scred, M_NSMBDEV);
	free(sdp, M_NSMBDEV);
	return;
}

#ifdef COMPAT_FREEBSD32
static void
smbioc_ossn32_to_ossn(struct smbioc_ossn *ossn, const void *data)
{
	const struct smbioc_ossn32 *ossn32;
	size_t copysize;

	ossn32 = data;
	ossn->ioc_opt = ossn32->ioc_opt;
	ossn->ioc_svlen = ossn32->ioc_svlen;
	ossn->ioc_server = __USER_CAP((void *)(uintptr_t)ossn32->ioc_server,
	    ossn32->ioc_svlen);
	ossn->ioc_lolen = ossn32->ioc_lolen;
	ossn->ioc_local = __USER_CAP((void *)(uintptr_t)ossn32->ioc_local,
	    ossn32->ioc_lolen);
	/* Do not include padding */
	copysize = min(
	    sizeof(*ossn) - offsetof(struct smbioc_ossn, ioc_srvname),
	    sizeof(*ossn32) - offsetof(struct smbioc_ossn32, ioc_srvname));
	memcpy(__unbounded_addressof(ossn->ioc_srvname),
	    __unbounded_addressof(ossn32->ioc_srvname), copysize);
}

static void
smbioc_rq32_to_rq(struct smbioc_rq *rq, const void *data)
{
	const struct smbioc_rq32 *rq32;

	rq32 = data;
	rq->ioc_cmd = rq32->ioc_cmd;
	rq->ioc_twc = rq32->ioc_twc;
	rq->ioc_twords = __USER_CAP((void *)(uintptr_t)rq32->ioc_twords,
	    rq32->ioc_twc);
	rq->ioc_tbc = rq32->ioc_tbc;
	rq->ioc_tbytes = __USER_CAP((void *)(uintptr_t)rq32->ioc_tbytes,
	    rq32->ioc_tbc);
	rq->ioc_rpbufsz = rq32->ioc_rpbufsz;
	rq->ioc_rpbuf = __USER_CAP((char *)(uintptr_t)rq32->ioc_rpbuf,
	    rq32->ioc_rpbufsz);
	memcpy(&rq->ioc_rwc, &rq32->ioc_rwc,
	    sizeof(*rq) - offsetof(struct smbioc_rq, ioc_rwc));
}

static void
smbioc_rq32_from_rq(void *data, const struct smbioc_rq *rq)
{
	struct smbioc_rq32 *rq32;

	rq32 = data;
	/* Don't update pointers, the kernel doesn't change them. */
	rq32->ioc_cmd = rq->ioc_cmd;
	rq32->ioc_twc = rq->ioc_twc;
	rq32->ioc_tbc = rq->ioc_tbc;
	rq32->ioc_rpbufsz = rq->ioc_rpbufsz;
	memcpy(&rq32->ioc_rwc, &rq->ioc_rwc,
	    sizeof(*rq32) - offsetof(struct smbioc_rq32, ioc_rwc));
}

static void
smbioc_t2rq32_to_t2rq(struct smbioc_t2rq *t2rq, const void *data)
{
	const struct smbioc_t2rq32 *t2rq32;

	t2rq32 = data;
	memset(t2rq, 0, sizeof(*t2rq));
	memcpy(&t2rq->ioc_setup, &t2rq32->ioc_setup, sizeof(t2rq->ioc_setup));
	t2rq->ioc_setupcnt = t2rq32->ioc_setupcnt;
	t2rq->ioc_name = __USER_CAP_STR((char *)(uintptr_t)t2rq32->ioc_name);
	t2rq->ioc_tparamcnt = t2rq32->ioc_tparamcnt;
	t2rq->ioc_tparam = __USER_CAP((void *)(uintptr_t)t2rq32->ioc_tparam,
	    t2rq32->ioc_tparamcnt);
	t2rq->ioc_tdatacnt = t2rq32->ioc_tdatacnt;
	t2rq->ioc_tdata = __USER_CAP((void *)(uintptr_t)t2rq32->ioc_tdata,
	    t2rq32->ioc_tdatacnt);
	t2rq->ioc_rparamcnt = t2rq32->ioc_rparamcnt;
	t2rq->ioc_rparam = __USER_CAP((void *)(uintptr_t)t2rq32->ioc_rparam,
	    t2rq32->ioc_rparamcnt);
	t2rq->ioc_rdatacnt = t2rq32->ioc_rdatacnt;
	t2rq->ioc_rdata = __USER_CAP((void *)(uintptr_t)t2rq32->ioc_rdata,
	    t2rq32->ioc_rdatacnt);
}

static void
smbioc_t2rq32_from_t2rq(void *data, const struct smbioc_t2rq *t2rq)
{
	struct smbioc_t2rq32 *t2rq32;

	t2rq32 = data;
	/* Don't update pointers, the kernel doesn't change them. */
	memcpy(&t2rq32->ioc_setup, &t2rq->ioc_setup, sizeof(t2rq32->ioc_setup));
	t2rq32->ioc_setupcnt = t2rq->ioc_setupcnt;
	t2rq32->ioc_tparamcnt = t2rq->ioc_tparamcnt;
	t2rq32->ioc_tdatacnt = t2rq->ioc_tdatacnt;
	t2rq32->ioc_rparamcnt = t2rq->ioc_rparamcnt;
	t2rq32->ioc_rdatacnt = t2rq->ioc_rdatacnt;
}

static void
smbioc_lookup32_to_lookup(struct smbioc_lookup *lookup, void *data)
{
	struct smbioc_lookup32 *lookup32;

	lookup32 = data;
	memset(lookup, 0, sizeof(*lookup));
	lookup->ioc_level = lookup32->ioc_level;
	lookup->ioc_flags = lookup32->ioc_flags;
	smbioc_ossn32_to_ossn(&lookup->ioc_ssn, &lookup32->ioc_ssn);
	memcpy(&lookup->ioc_sh, &lookup32->ioc_sh, sizeof(lookup->ioc_sh));
}

static void
smbioc_rw32_to_rw(struct smbioc_rw *rw, const void *data)
{
	const struct smbioc_rw32 *rw32;

	rw32 = data;
	memset(rw, 0, sizeof(*rw));
	rw->ioc_fh = rw32->ioc_fh;
	rw->ioc_base = __USER_CAP((char *)(uintptr_t)rw32->ioc_base,
	    rw32->ioc_cnt);
	rw->ioc_offset = rw32->ioc_offset;
	rw->ioc_cnt = rw32->ioc_cnt;
}

static void
smbioc_rw32_from_rw(void *data, const struct smbioc_rw *rw)
{
	struct smbioc_rw32 *rw32;

	rw32 = data;
	/* Don't update pointers, the kernel doesn't change them. */
	rw32->ioc_fh = rw->ioc_fh;
	rw32->ioc_offset = rw->ioc_offset;
	rw32->ioc_cnt = rw->ioc_cnt;
}
#endif /* COMPAT_FREEBSD32 */

#ifdef COMPAT_FREEBSD64
static void
smbioc_ossn64_to_ossn(struct smbioc_ossn *ossn, const void *data)
{
	const struct smbioc_ossn64 *ossn64;
	size_t copysize;

	ossn64 = data;
	ossn->ioc_opt = ossn64->ioc_opt;
	ossn->ioc_svlen = ossn64->ioc_svlen;
	ossn->ioc_server = __USER_CAP((void *)(uintptr_t)ossn64->ioc_server,
	    ossn64->ioc_svlen);
	ossn->ioc_lolen = ossn64->ioc_lolen;
	ossn->ioc_local = __USER_CAP((void *)(uintptr_t)ossn64->ioc_local,
	    ossn64->ioc_lolen);
	/* Do not include padding */
	copysize = min(
	    sizeof(*ossn) - offsetof(struct smbioc_ossn, ioc_srvname),
	    sizeof(*ossn64) - offsetof(struct smbioc_ossn64, ioc_srvname));
	memcpy(__unbounded_addressof(ossn->ioc_srvname),
	    __unbounded_addressof(ossn64->ioc_srvname), copysize);
}

static void
smbioc_rq64_to_rq(struct smbioc_rq *rq, const void *data)
{
	const struct smbioc_rq64 *rq64;

	rq64 = data;
	rq->ioc_cmd = rq64->ioc_cmd;
	rq->ioc_twc = rq64->ioc_twc;
	rq->ioc_twords = __USER_CAP((void *)(uintptr_t)rq64->ioc_twords,
	    rq64->ioc_twc);
	rq->ioc_tbc = rq64->ioc_tbc;
	rq->ioc_tbytes = __USER_CAP((void *)(uintptr_t)rq64->ioc_tbytes,
	    rq64->ioc_tbc);
	rq->ioc_rpbufsz = rq64->ioc_rpbufsz;
	rq->ioc_rpbuf = __USER_CAP((char *)(uintptr_t)rq64->ioc_rpbuf,
	    rq64->ioc_rpbufsz);
	memcpy(&rq->ioc_rwc, &rq64->ioc_rwc,
	    sizeof(*rq) - offsetof(struct smbioc_rq, ioc_rwc));
}

static void
smbioc_rq64_from_rq(void *data, const struct smbioc_rq *rq)
{
	struct smbioc_rq64 *rq64;

	rq64 = data;
	/* Don't update pointers, the kernel doesn't change them. */
	rq64->ioc_cmd = rq->ioc_cmd;
	rq64->ioc_twc = rq->ioc_twc;
	rq64->ioc_tbc = rq->ioc_tbc;
	rq64->ioc_rpbufsz = rq->ioc_rpbufsz;
	memcpy(&rq64->ioc_rwc, &rq->ioc_rwc,
	    sizeof(*rq64) - offsetof(struct smbioc_rq64, ioc_rwc));
}

static void
smbioc_t2rq64_to_t2rq(struct smbioc_t2rq *t2rq, const void *data)
{
	const struct smbioc_t2rq64 *t2rq64;

	t2rq64 = data;
	memset(t2rq, 0, sizeof(*t2rq));
	memcpy(&t2rq->ioc_setup, &t2rq64->ioc_setup, sizeof(t2rq->ioc_setup));
	t2rq->ioc_setupcnt = t2rq64->ioc_setupcnt;
	t2rq->ioc_name = __USER_CAP_STR((char *)(uintptr_t)t2rq64->ioc_name);
	t2rq->ioc_tparamcnt = t2rq64->ioc_tparamcnt;
	t2rq->ioc_tparam = __USER_CAP((void *)(uintptr_t)t2rq64->ioc_tparam,
	    t2rq64->ioc_tparamcnt);
	t2rq->ioc_tdatacnt = t2rq64->ioc_tdatacnt;
	t2rq->ioc_tdata = __USER_CAP((void *)(uintptr_t)t2rq64->ioc_tdata,
	    t2rq64->ioc_tdatacnt);
	t2rq->ioc_rparamcnt = t2rq64->ioc_rparamcnt;
	t2rq->ioc_rparam = __USER_CAP((void *)(uintptr_t)t2rq64->ioc_rparam,
	    t2rq64->ioc_rparamcnt);
	t2rq->ioc_rdatacnt = t2rq64->ioc_rdatacnt;
	t2rq->ioc_rdata = __USER_CAP((void *)(uintptr_t)t2rq64->ioc_rdata,
	    t2rq64->ioc_rdatacnt);
}

static void
smbioc_t2rq64_from_t2rq(void *data, const struct smbioc_t2rq *t2rq)
{
	struct smbioc_t2rq64 *t2rq64;

	t2rq64 = data;
	/* Don't update pointers, the kernel doesn't change them. */
	memcpy(&t2rq64->ioc_setup, &t2rq->ioc_setup, sizeof(t2rq64->ioc_setup));
	t2rq64->ioc_setupcnt = t2rq->ioc_setupcnt;
	t2rq64->ioc_tparamcnt = t2rq->ioc_tparamcnt;
	t2rq64->ioc_tdatacnt = t2rq->ioc_tdatacnt;
	t2rq64->ioc_rparamcnt = t2rq->ioc_rparamcnt;
	t2rq64->ioc_rdatacnt = t2rq->ioc_rdatacnt;
}

static void
smbioc_lookup64_to_lookup(struct smbioc_lookup *lookup, void *data)
{
	struct smbioc_lookup64 *lookup64;

	lookup64 = data;
	memset(lookup, 0, sizeof(*lookup));
	lookup->ioc_level = lookup64->ioc_level;
	lookup->ioc_flags = lookup64->ioc_flags;
	smbioc_ossn64_to_ossn(&lookup->ioc_ssn, &lookup64->ioc_ssn);
	memcpy(&lookup->ioc_sh, &lookup64->ioc_sh, sizeof(lookup->ioc_sh));
}

static void
smbioc_rw64_to_rw(struct smbioc_rw *rw, const void *data)
{
	const struct smbioc_rw64 *rw64;

	rw64 = data;
	memset(rw, 0, sizeof(*rw));
	rw->ioc_fh = rw64->ioc_fh;
	rw->ioc_base = __USER_CAP((char *)(uintptr_t)rw64->ioc_base,
	    rw64->ioc_cnt);
	rw->ioc_offset = rw64->ioc_offset;
	rw->ioc_cnt = rw64->ioc_cnt;
}

static void
smbioc_rw64_from_rw(void *data, const struct smbioc_rw *rw)
{
	struct smbioc_rw64 *rw64;

	rw64 = data;
	/* Don't update pointers, the kernel doesn't change them. */
	rw64->ioc_fh = rw->ioc_fh;
	rw64->ioc_offset = rw->ioc_offset;
	rw64->ioc_cnt = rw->ioc_cnt;
}
#endif /* COMPAT_FREEBSD64 */

static int
nsmb_dev_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flag, struct thread *td)
{
	struct smb_dev *sdp;
	struct smb_vc *vcp;
	struct smb_share *ssp;
	struct smb_cred *scred;
	struct smbioc_ossn *ossn;
	struct smbioc_rq *rq;
	struct smbioc_t2rq *t2rq;
	struct smbioc_lookup *lookup;
	struct smbioc_rw *rwrq;
#if defined(COMPAT_FREEBSD32) || defined(COMPAT_FREEBSD64)
	union {
		struct smbioc_ossn ossn;
		struct smbioc_rq rq;
		struct smbioc_t2rq t2rq;
		struct smbioc_lookup lookup;
		struct smbioc_rw rw;
	} u;
#endif
	int error = 0;

	error = devfs_get_cdevpriv((void **)&sdp);
	if (error)
		return (error);
	scred = malloc(sizeof(struct smb_cred), M_NSMBDEV, M_WAITOK);
	SMB_LOCK();
	smb_makescred(scred, td, NULL);
	switch (cmd) {
	    case SMBIOC_OPENSESSION:
#ifdef COMPAT_FREEBSD32
	    case SMBIOC_OPENSESSION32:
#endif
#ifdef COMPAT_FREEBSD64
	    case SMBIOC_OPENSESSION64:
#endif
		if (sdp->sd_vc) {
			error = EISCONN;
			goto out;
		}
#ifdef COMPAT_FREEBSD32
		if (cmd == SMBIOC_OPENSESSION32) {
			ossn = &u.ossn;
			smbioc_ossn32_to_ossn(ossn, data);
		} else
#endif
#ifdef COMPAT_FREEBSD64
		if (cmd == SMBIOC_OPENSESSION64) {
			ossn = &u.ossn;
			smbioc_ossn64_to_ossn(ossn, data);
		} else
#endif
			ossn = (struct smbioc_ossn *)data;

		error = smb_usr_opensession(ossn, scred, &vcp);
		if (error)
			break;
		sdp->sd_vc = vcp;
		smb_vc_unlock(vcp);
		sdp->sd_level = SMBL_VC;
		break;
	    case SMBIOC_OPENSHARE:
		if (sdp->sd_share) {
			error = EISCONN;
			goto out;
		}
		if (sdp->sd_vc == NULL) {
			error = ENOTCONN;
			goto out;
		}
		error = smb_usr_openshare(sdp->sd_vc,
		    (struct smbioc_oshare*)data, scred, &ssp);
		if (error)
			break;
		sdp->sd_share = ssp;
		smb_share_unlock(ssp);
		sdp->sd_level = SMBL_SHARE;
		break;
	    case SMBIOC_REQUEST:
#ifdef COMPAT_FREEBSD32
	    case SMBIOC_REQUEST32:
#endif
#ifdef COMPAT_FREEBSD64
	    case SMBIOC_REQUEST64:
#endif
		if (sdp->sd_share == NULL) {
			error = ENOTCONN;
			goto out;
		}
#ifdef COMPAT_FREEBSD32
		if (cmd == SMBIOC_REQUEST32) {
			rq = &u.rq;
			smbioc_rq32_to_rq(rq, data);
		} else
#endif
#ifdef COMPAT_FREEBSD64
		if (cmd == SMBIOC_REQUEST64) {
			rq = &u.rq;
			smbioc_rq64_to_rq(rq, data);
		} else
#endif
			rq = (struct smbioc_rq *)data;
		error = smb_usr_simplerequest(sdp->sd_share, rq, scred);
#ifdef COMPAT_FREEBSD32
		if (cmd == SMBIOC_OPENSESSION32)
			smbioc_rq32_from_rq(data, rq);
#endif
#ifdef COMPAT_FREEBSD64
		if (cmd == SMBIOC_OPENSESSION64)
			smbioc_rq64_from_rq(data, rq);
#endif
		break;
	    case SMBIOC_T2RQ:
#ifdef COMPAT_FREEBSD32
	    case SMBIOC_T2RQ32:
#endif
#ifdef COMPAT_FREEBSD64
	    case SMBIOC_T2RQ64:
#endif
		if (sdp->sd_share == NULL) {
			error = ENOTCONN;
			goto out;
		}
#ifdef COMPAT_FREEBSD32
		if (cmd == SMBIOC_T2RQ32) {
			t2rq = &u.t2rq;
			smbioc_t2rq32_to_t2rq(t2rq, data);
		} else
#endif
#ifdef COMPAT_FREEBSD64
		if (cmd == SMBIOC_T2RQ64) {
			t2rq = &u.t2rq;
			smbioc_t2rq64_to_t2rq(t2rq, data);
		} else
#endif
			t2rq = (struct smbioc_t2rq *)data;
		error = smb_usr_t2request(sdp->sd_share, t2rq, scred);
#ifdef COMPAT_FREEBSD32
		if (cmd == SMBIOC_T2RQ32)
			smbioc_t2rq32_from_t2rq(data, t2rq);
#endif
#ifdef COMPAT_FREEBSD64
		if (cmd == SMBIOC_T2RQ64)
			smbioc_t2rq64_from_t2rq(data, t2rq);
#endif
		break;
	    case SMBIOC_SETFLAGS: {
		struct smbioc_flags *fl = (struct smbioc_flags*)data;
		int on;

		if (fl->ioc_level == SMBL_VC) {
			if (fl->ioc_mask & SMBV_PERMANENT) {
				on = fl->ioc_flags & SMBV_PERMANENT;
				if ((vcp = sdp->sd_vc) == NULL) {
					error = ENOTCONN;
					goto out;
				}
				error = smb_vc_get(vcp, scred);
				if (error)
					break;
				if (on && (vcp->obj.co_flags & SMBV_PERMANENT) == 0) {
					vcp->obj.co_flags |= SMBV_PERMANENT;
					smb_vc_ref(vcp);
				} else if (!on && (vcp->obj.co_flags & SMBV_PERMANENT)) {
					vcp->obj.co_flags &= ~SMBV_PERMANENT;
					smb_vc_rele(vcp, scred);
				}
				smb_vc_put(vcp, scred);
			} else
				error = EINVAL;
		} else if (fl->ioc_level == SMBL_SHARE) {
			if (fl->ioc_mask & SMBS_PERMANENT) {
				on = fl->ioc_flags & SMBS_PERMANENT;
				if ((ssp = sdp->sd_share) == NULL) {
					error = ENOTCONN;
					goto out;
				}
				error = smb_share_get(ssp, scred);
				if (error)
					break;
				if (on && (ssp->obj.co_flags & SMBS_PERMANENT) == 0) {
					ssp->obj.co_flags |= SMBS_PERMANENT;
					smb_share_ref(ssp);
				} else if (!on && (ssp->obj.co_flags & SMBS_PERMANENT)) {
					ssp->obj.co_flags &= ~SMBS_PERMANENT;
					smb_share_rele(ssp, scred);
				}
				smb_share_put(ssp, scred);
			} else
				error = EINVAL;
			break;
		} else
			error = EINVAL;
		break;
	    }
	    case SMBIOC_LOOKUP:
#ifdef COMPAT_FREEBSD32
	    case SMBIOC_LOOKUP32:
#endif
#ifdef COMPAT_FREEBSD64
	    case SMBIOC_LOOKUP64:
#endif
		if (sdp->sd_vc || sdp->sd_share) {
			error = EISCONN;
			goto out;
		}
		vcp = NULL;
		ssp = NULL;
#ifdef COMPAT_FREEBSD32
		if (cmd == SMBIOC_LOOKUP32) {
			lookup = &u.lookup;
			smbioc_lookup32_to_lookup(lookup, data);
		} else
#endif
#ifdef COMPAT_FREEBSD64
		if (cmd == SMBIOC_LOOKUP64) {
			lookup = &u.lookup;
			smbioc_lookup64_to_lookup(lookup, data);
		} else
#endif
			lookup = (struct smbioc_lookup *)data;
		error = smb_usr_lookup(lookup, scred, &vcp, &ssp);
		if (error)
			break;
		if (vcp) {
			sdp->sd_vc = vcp;
			smb_vc_unlock(vcp);
			sdp->sd_level = SMBL_VC;
		}
		if (ssp) {
			sdp->sd_share = ssp;
			smb_share_unlock(ssp);
			sdp->sd_level = SMBL_SHARE;
		}
		break;
	    case SMBIOC_READ: case SMBIOC_WRITE:
#ifdef COMPAT_FREEBSD32
	    case SMBIOC_READ32: case SMBIOC_WRITE32:
#endif
#ifdef COMPAT_FREEBSD64
	    case SMBIOC_READ64: case SMBIOC_WRITE64:
#endif
	    {
		struct uio auio;
		struct iovec iov;

		if ((ssp = sdp->sd_share) == NULL) {
			error = ENOTCONN;
			goto out;
	 	}
#ifdef COMPAT_FREEBSD32
		if (cmd == SMBIOC_READ32 || cmd == SMBIOC_WRITE32) {
			rwrq = &u.rw;
			smbioc_rw32_to_rw(rwrq, data);
		} else
#endif
#ifdef COMPAT_FREEBSD64
		if (cmd == SMBIOC_READ64 || cmd == SMBIOC_WRITE64) {
			rwrq = &u.rw;
			smbioc_rw64_to_rw(rwrq, data);
		} else
#endif
			rwrq = (struct smbioc_rw *)data;
		IOVEC_INIT_C(&iov, rwrq->ioc_base, rwrq->ioc_cnt);
		auio.uio_iov = &iov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = rwrq->ioc_offset;
		auio.uio_resid = rwrq->ioc_cnt;
		auio.uio_segflg = UIO_USERSPACE;
		auio.uio_rw = (cmd == SMBIOC_READ) ? UIO_READ : UIO_WRITE;
		auio.uio_td = td;
		if (cmd == SMBIOC_READ)
			error = smb_read(ssp, rwrq->ioc_fh, &auio, scred);
		else
			error = smb_write(ssp, rwrq->ioc_fh, &auio, scred);
		rwrq->ioc_cnt -= auio.uio_resid;
#ifdef COMPAT_FREEBSD32
		if (cmd == SMBIOC_READ32 || cmd == SMBIOC_WRITE32)
			smbioc_rw32_from_rw(data, rwrq);
#endif
#ifdef COMPAT_FREEBSD64
		if (cmd == SMBIOC_READ64 || cmd == SMBIOC_WRITE64)
			smbioc_rw64_from_rw(data, rwrq);
#endif
		break;
	    }
	    default:
		error = ENODEV;
	}
out:
	free(scred, M_NSMBDEV);
	SMB_UNLOCK();
	return error;
}

static int
nsmb_dev_load(module_t mod, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	    case MOD_LOAD:
		error = smb_sm_init();
		if (error)
			break;
		error = smb_iod_init();
		if (error) {
			smb_sm_done();
			break;
		}
		error = nsmb_dev_init();
		if (error)
			break;
		sx_init(&smb_lock, "samba device lock");
		break;
	    case MOD_UNLOAD:
		smb_iod_done();
		error = smb_sm_done();
		if (error)
			break;
		nsmb_dev_destroy();
		sx_destroy(&smb_lock);
		break;
	    default:
		error = EINVAL;
		break;
	}
	return error;
}

DEV_MODULE (dev_netsmb, nsmb_dev_load, 0);

int
smb_dev2share(int fd, int mode, struct smb_cred *scred,
	struct smb_share **sspp, struct smb_dev **ssdp)
{
	struct file *fp, *fptmp;
	struct smb_dev *sdp;
	struct smb_share *ssp;
	struct thread *td;
	int error;

	td = curthread;
	error = fget(td, fd, &cap_read_rights, &fp);
	if (error)
		return (error);
	fptmp = td->td_fpop;
	td->td_fpop = fp;
	error = devfs_get_cdevpriv((void **)&sdp);
	td->td_fpop = fptmp;
	fdrop(fp, td);
	if (error || sdp == NULL)
		return (error);
	SMB_LOCK();
	*ssdp = sdp;
	ssp = sdp->sd_share;
	if (ssp == NULL) {
		SMB_UNLOCK();
		return (ENOTCONN);
	}
	error = smb_share_get(ssp, scred);
	if (error == 0) {
		sdp->refcount++;
		*sspp = ssp;
	}
	SMB_UNLOCK();
	return error;
}
// CHERI CHANGES START
// {
//   "updated": 20221205,
//   "target_type": "kernel",
//   "changes": [
//     "ioctl:misc",
//     "iovec-macros"
//   ],
//   "changes_purecap": [
//      "subobject_bounds"
//   ]
// }
// CHERI CHANGES END
