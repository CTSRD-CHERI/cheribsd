/**************************************************************************

Copyright (c) 2007, Chelsio Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Neither the name of the Chelsio Corporation nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

***************************************************************************/
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"

#ifdef TCP_OFFLOAD
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/pciio.h>
#include <sys/conf.h>
#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>
#include <sys/ioccom.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/linker.h>
#include <sys/firmware.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/proc.h>
#include <sys/queue.h>

#include <netinet/in.h>


#include <vm/vm.h>
#include <vm/pmap.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include <linux/idr.h>
#include <ulp/iw_cxgb/iw_cxgb_ib_intfc.h>


#include <cxgb_include.h>
#include <ulp/iw_cxgb/iw_cxgb_wr.h>
#include <ulp/iw_cxgb/iw_cxgb_hal.h>
#include <ulp/iw_cxgb/iw_cxgb_provider.h>
#include <ulp/iw_cxgb/iw_cxgb_cm.h>
#include <ulp/iw_cxgb/iw_cxgb.h>
#include <ulp/iw_cxgb/iw_cxgb_resource.h>
#include <ulp/iw_cxgb/iw_cxgb_user.h>

static int
iwch_modify_port(struct ib_device *ibdev,
			    u8 port, int port_modify_mask,
			    struct ib_port_modify *props)
{
	return (-ENOSYS);
}

static struct ib_ah *
iwch_ah_create(struct ib_pd *pd,
				    struct ib_ah_attr *ah_attr)
{
	return ERR_PTR(-ENOSYS);
}

static int
iwch_ah_destroy(struct ib_ah *ah)
{
	return (-ENOSYS);
}

static int iwch_multicast_attach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	return (-ENOSYS);
}

static int
iwch_multicast_detach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	return (-ENOSYS);
}

static int
iwch_process_mad(struct ib_device *ibdev,
			    int mad_flags,
			    u8 port_num,
			    struct ib_wc *in_wc,
			    struct ib_grh *in_grh,
			    struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	return (-ENOSYS);
}

static int
iwch_dealloc_ucontext(struct ib_ucontext *context)
{
	struct iwch_dev *rhp = to_iwch_dev(context->device);
	struct iwch_ucontext *ucontext = to_iwch_ucontext(context);
	struct iwch_mm_entry *mm, *tmp;

	CTR2(KTR_IW_CXGB, "%s context %p", __FUNCTION__, context);
	TAILQ_FOREACH_SAFE(mm, &ucontext->mmaps, entry, tmp) {
		TAILQ_REMOVE(&ucontext->mmaps, mm, entry);
		cxfree(mm);
	}
	cxio_release_ucontext(&rhp->rdev, &ucontext->uctx);
	cxfree(ucontext);
	return 0;
}

static struct ib_ucontext *
iwch_alloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata)
{
	struct iwch_ucontext *context;
	struct iwch_dev *rhp = to_iwch_dev(ibdev);

	CTR2(KTR_IW_CXGB, "%s ibdev %p", __FUNCTION__, ibdev);
	context = malloc(sizeof(*context), M_DEVBUF, M_ZERO|M_NOWAIT);
	if (!context)
		return ERR_PTR(-ENOMEM);
	cxio_init_ucontext(&rhp->rdev, &context->uctx);
	TAILQ_INIT(&context->mmaps);
	mtx_init(&context->mmap_lock, "ucontext mmap", NULL, MTX_DEF);
	return &context->ibucontext;
}

static int
iwch_destroy_cq(struct ib_cq *ib_cq)
{
	struct iwch_cq *chp;

	CTR2(KTR_IW_CXGB, "%s ib_cq %p", __FUNCTION__, ib_cq);
	chp = to_iwch_cq(ib_cq);

	remove_handle(chp->rhp, &chp->rhp->cqidr, chp->cq.cqid);
	mtx_lock(&chp->lock);
	if (--chp->refcnt)
		msleep(chp, &chp->lock, 0, "iwch_destroy_cq", 0);
	mtx_unlock(&chp->lock);

	cxio_destroy_cq(&chp->rhp->rdev, &chp->cq);
	cxfree(chp);
	return 0;
}

static struct ib_cq *
iwch_create_cq(struct ib_device *ibdev, struct ib_cq_init_attr *attr,
			     struct ib_ucontext *ib_context,
			     struct ib_udata *udata)
{
	struct iwch_dev *rhp;
	struct iwch_cq *chp;
	struct iwch_create_cq_resp uresp;
	struct iwch_create_cq_req ureq;
	struct iwch_ucontext *ucontext = NULL;
	static int warned;
	size_t resplen;
	int entries = attr->cqe;

	CTR3(KTR_IW_CXGB, "%s ib_dev %p entries %d", __FUNCTION__, ibdev, entries);
	rhp = to_iwch_dev(ibdev);
	chp = malloc(sizeof(*chp), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (!chp) {
		return ERR_PTR(-ENOMEM);
	}
	if (ib_context) {
		ucontext = to_iwch_ucontext(ib_context);
		if (!t3a_device(rhp)) {
			if (ib_copy_from_udata(&ureq, udata, sizeof (ureq))) {
				cxfree(chp);
				return ERR_PTR(-EFAULT);
			}
			chp->user_rptr_addr = (u32 /*__user */*)(unsigned long)ureq.user_rptr_addr;
		}
	}

	if (t3a_device(rhp)) {

		/*
		 * T3A: Add some fluff to handle extra CQEs inserted
		 * for various errors.
		 * Additional CQE possibilities:
		 *      TERMINATE,
		 *      incoming RDMA WRITE Failures
		 *      incoming RDMA READ REQUEST FAILUREs
		 * NOTE: We cannot ensure the CQ won't overflow.
		 */
		entries += 16;
	}
	entries = roundup_pow_of_two(entries);
	chp->cq.size_log2 = ilog2(entries);

	if (cxio_create_cq(&rhp->rdev, &chp->cq, !ucontext)) {
		cxfree(chp);
		return ERR_PTR(-ENOMEM);
	}
	chp->rhp = rhp;
	chp->ibcq.cqe = 1 << chp->cq.size_log2;
	mtx_init(&chp->lock, "cxgb cq", NULL, MTX_DEF|MTX_DUPOK);
	chp->refcnt = 1;
	if (insert_handle(rhp, &rhp->cqidr, chp, chp->cq.cqid)) {
		cxio_destroy_cq(&chp->rhp->rdev, &chp->cq);
		cxfree(chp);
		return ERR_PTR(-ENOMEM);
	}

	if (ucontext) {
		struct iwch_mm_entry *mm;

		mm = kmalloc(sizeof *mm, M_NOWAIT);
		if (!mm) {
			iwch_destroy_cq(&chp->ibcq);
			return ERR_PTR(-ENOMEM);
		}
		uresp.cqid = chp->cq.cqid;
		uresp.size_log2 = chp->cq.size_log2;
		mtx_lock(&ucontext->mmap_lock);
		uresp.key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		mtx_unlock(&ucontext->mmap_lock);
		mm->key = uresp.key;
		mm->addr = vtophys(chp->cq.queue);
               	if (udata->outlen < sizeof uresp) {
                	if (!warned++)
                        	CTR1(KTR_IW_CXGB, "%s Warning - "
                                	"downlevel libcxgb3 (non-fatal).\n",
					__func__);
                       	mm->len = PAGE_ALIGN((1UL << uresp.size_log2) *
                       				sizeof(struct t3_cqe));
                       	resplen = sizeof(struct iwch_create_cq_resp_v0);
               	} else {
                	mm->len = PAGE_ALIGN(((1UL << uresp.size_log2) + 1) *
                        			sizeof(struct t3_cqe));
                       	uresp.memsize = mm->len;
                      	resplen = sizeof uresp;
               	}
              	if (ib_copy_to_udata(udata, &uresp, resplen)) {
			cxfree(mm);
			iwch_destroy_cq(&chp->ibcq);
			return ERR_PTR(-EFAULT);
		}
		insert_mmap(ucontext, mm);
	}
	CTR4(KTR_IW_CXGB, "created cqid 0x%0x chp %p size 0x%0x, dma_addr 0x%0llx",
	     chp->cq.cqid, chp, (1 << chp->cq.size_log2),
	     (unsigned long long) chp->cq.dma_addr);
	return &chp->ibcq;
}

static int
iwch_resize_cq(struct ib_cq *cq __unused, int cqe __unused,
    struct ib_udata *udata __unused)
{

	return (-ENOSYS);
}

static int
iwch_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct iwch_dev *rhp;
	struct iwch_cq *chp;
	enum t3_cq_opcode cq_op;
	int err;
	u32 rptr;

	chp = to_iwch_cq(ibcq);
	rhp = chp->rhp;
	if ((flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED)
		cq_op = CQ_ARM_SE;
	else
		cq_op = CQ_ARM_AN;
	if (chp->user_rptr_addr) {
		if (copyin(chp->user_rptr_addr, &rptr, sizeof(rptr)))
			return (-EFAULT);
		mtx_lock(&chp->lock);
		chp->cq.rptr = rptr;
	} else
		mtx_lock(&chp->lock);
	CTR2(KTR_IW_CXGB, "%s rptr 0x%x", __FUNCTION__, chp->cq.rptr);
	err = cxio_hal_cq_op(&rhp->rdev, &chp->cq, cq_op, 0);
	mtx_unlock(&chp->lock);
	if (err < 0)
		log(LOG_ERR, "Error %d rearming CQID 0x%x\n", err,
		       chp->cq.cqid);
	if (err > 0 && !(flags & IB_CQ_REPORT_MISSED_EVENTS))
		err = 0;
	return err;
}

static int
iwch_mmap(struct ib_ucontext *context __unused, struct vm_area_struct *vma __unused)
{

	return (-ENOSYS);
}

static int iwch_deallocate_pd(struct ib_pd *pd)
{
	struct iwch_dev *rhp;
	struct iwch_pd *php;

	php = to_iwch_pd(pd);
	rhp = php->rhp;
	CTR3(KTR_IW_CXGB, "%s ibpd %p pdid 0x%x", __FUNCTION__, pd, php->pdid);
	cxio_hal_put_pdid(rhp->rdev.rscp, php->pdid);
	cxfree(php);
	return 0;
}

static struct ib_pd *iwch_allocate_pd(struct ib_device *ibdev,
			       struct ib_ucontext *context,
			       struct ib_udata *udata)
{
	struct iwch_pd *php;
	u32 pdid;
	struct iwch_dev *rhp;

	CTR2(KTR_IW_CXGB, "%s ibdev %p", __FUNCTION__, ibdev);
	rhp = (struct iwch_dev *) ibdev;
	pdid = cxio_hal_get_pdid(rhp->rdev.rscp);
	if (!pdid)
		return ERR_PTR(-EINVAL);
	php = malloc(sizeof(*php), M_DEVBUF, M_ZERO|M_NOWAIT);
	if (!php) {
		cxio_hal_put_pdid(rhp->rdev.rscp, pdid);
		return ERR_PTR(-ENOMEM);
	}
	php->pdid = pdid;
	php->rhp = rhp;
	if (context) {
		if (ib_copy_to_udata(udata, &php->pdid, sizeof (__u32))) {
			iwch_deallocate_pd(&php->ibpd);
			return ERR_PTR(-EFAULT);
		}
	}
	CTR3(KTR_IW_CXGB, "%s pdid 0x%0x ptr 0x%p", __FUNCTION__, pdid, php);
	return &php->ibpd;
}

static int iwch_dereg_mr(struct ib_mr *ib_mr)
{
	struct iwch_dev *rhp;
	struct iwch_mr *mhp;
	u32 mmid;

	CTR2(KTR_IW_CXGB, "%s ib_mr %p", __FUNCTION__, ib_mr);
	/* There can be no memory windows */
	if (atomic_load_acq_int(&ib_mr->usecnt.counter))
		return (-EINVAL);

	mhp = to_iwch_mr(ib_mr);
	rhp = mhp->rhp;
	mmid = mhp->attr.stag >> 8;
	cxio_dereg_mem(&rhp->rdev, mhp->attr.stag, mhp->attr.pbl_size,
		       mhp->attr.pbl_addr);
	iwch_free_pbl(mhp);
	remove_handle(rhp, &rhp->mmidr, mmid);
	if (mhp->kva)
		cxfree((void *) (unsigned long) mhp->kva);
	if (mhp->umem)
		ib_umem_release(mhp->umem);
	CTR3(KTR_IW_CXGB, "%s mmid 0x%x ptr %p", __FUNCTION__, mmid, mhp);
	cxfree(mhp);
	return 0;
}

static struct ib_mr *iwch_register_phys_mem(struct ib_pd *pd,
					struct ib_phys_buf *buffer_list,
					int num_phys_buf,
					int acc,
					u64 *iova_start)
{
	__be64 *page_list;
	int shift;
	u64 total_size;
	int npages;
	struct iwch_dev *rhp;
	struct iwch_pd *php;
	struct iwch_mr *mhp;
	int ret;

	CTR2(KTR_IW_CXGB, "%s ib_pd %p", __FUNCTION__, pd);
	php = to_iwch_pd(pd);
	rhp = php->rhp;

	mhp = malloc(sizeof(*mhp), M_DEVBUF, M_ZERO|M_NOWAIT);
	if (!mhp)
		return ERR_PTR(-ENOMEM);

	mhp->rhp = rhp;

	/* First check that we have enough alignment */
	if ((*iova_start & ~PAGE_MASK) != (buffer_list[0].addr & ~PAGE_MASK)) {
		ret = -EINVAL;
		goto err;
	}

	if (num_phys_buf > 1 &&
	    ((buffer_list[0].addr + buffer_list[0].size) & ~PAGE_MASK)) {
		ret = -EINVAL;
		goto err;
	}

	ret = build_phys_page_list(buffer_list, num_phys_buf, iova_start,
				   &total_size, &npages, &shift, &page_list);
	if (ret)
		goto err;

	ret = iwch_alloc_pbl(mhp, npages);
	if (ret) {
		cxfree(page_list);
		goto err_pbl;
	}

	ret = iwch_write_pbl(mhp, page_list, npages, 0);
	cxfree(page_list);
	if (ret)
		goto err;

	mhp->attr.pdid = php->pdid;
	mhp->attr.zbva = 0;

	mhp->attr.perms = iwch_ib_to_tpt_access(acc);
	mhp->attr.va_fbo = *iova_start;
	mhp->attr.page_size = shift - 12;

	mhp->attr.len = (u32) total_size;
	mhp->attr.pbl_size = npages;
	ret = iwch_register_mem(rhp, php, mhp, shift);
	if (ret)
		goto err_pbl;

	return &mhp->ibmr;

err_pbl:
	iwch_free_pbl(mhp);

err:
	cxfree(mhp);
	return ERR_PTR(ret);

}

static int iwch_reregister_phys_mem(struct ib_mr *mr,
				     int mr_rereg_mask,
				     struct ib_pd *pd,
	                             struct ib_phys_buf *buffer_list,
	                             int num_phys_buf,
	                             int acc, u64 * iova_start)
{

	struct iwch_mr mh, *mhp;
	struct iwch_pd *php;
	struct iwch_dev *rhp;
	__be64 *page_list = NULL;
	int shift = 0;
	u64 total_size;
	int npages = 0;
	int ret;

	CTR3(KTR_IW_CXGB, "%s ib_mr %p ib_pd %p", __FUNCTION__, mr, pd);

	/* There can be no memory windows */
	if (atomic_load_acq_int(&mr->usecnt.counter))
		return (-EINVAL);

	mhp = to_iwch_mr(mr);
	rhp = mhp->rhp;
	php = to_iwch_pd(mr->pd);

	/* make sure we are on the same adapter */
	if (rhp != php->rhp)
		return (-EINVAL);

	memcpy(&mh, mhp, sizeof *mhp);

	if (mr_rereg_mask & IB_MR_REREG_PD)
		php = to_iwch_pd(pd);
	if (mr_rereg_mask & IB_MR_REREG_ACCESS)
		mh.attr.perms = iwch_ib_to_tpt_access(acc);
	if (mr_rereg_mask & IB_MR_REREG_TRANS) {
		ret = build_phys_page_list(buffer_list, num_phys_buf,
					   iova_start,
					   &total_size, &npages,
					   &shift, &page_list);
		if (ret)
			return ret;
	}

	ret = iwch_reregister_mem(rhp, php, &mh, shift, npages);
	cxfree(page_list);
	if (ret) {
		return ret;
	}
	if (mr_rereg_mask & IB_MR_REREG_PD)
		mhp->attr.pdid = php->pdid;
	if (mr_rereg_mask & IB_MR_REREG_ACCESS)
		mhp->attr.perms = iwch_ib_to_tpt_access(acc);
	if (mr_rereg_mask & IB_MR_REREG_TRANS) {
		mhp->attr.zbva = 0;
		mhp->attr.va_fbo = *iova_start;
		mhp->attr.page_size = shift - 12;
		mhp->attr.len = (u32) total_size;
		mhp->attr.pbl_size = npages;
	}

	return 0;
}


static struct ib_mr *iwch_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				      u64 virt, int acc, struct ib_udata *udata,
				      int mr_id)
{
	__be64 *pages;
	int shift, n, len;
	int i, k, entry;
	int err = 0;
	struct iwch_dev *rhp;
	struct iwch_pd *php;
	struct iwch_mr *mhp;
	struct iwch_reg_user_mr_resp uresp;
	struct scatterlist *sg;
	
	CTR2(KTR_IW_CXGB, "%s ib_pd %p", __FUNCTION__, pd);

	php = to_iwch_pd(pd);
	rhp = php->rhp;
	mhp = malloc(sizeof(*mhp), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (!mhp)
		return ERR_PTR(-ENOMEM);

	mhp->rhp = rhp;

	mhp->umem = ib_umem_get(pd->uobject->context, start, length, acc, 0);
	if (IS_ERR(mhp->umem)) {
		err = PTR_ERR(mhp->umem);
		cxfree(mhp);
		return ERR_PTR(-err);
	}

	shift = ffs(mhp->umem->page_size) - 1;

	n = mhp->umem->nmap;

	err = iwch_alloc_pbl(mhp, n);
	if (err)
		goto err;

	pages = (__be64 *) kmalloc(n * sizeof(u64), M_NOWAIT);
	if (!pages) {
		err = -ENOMEM;
		goto err_pbl;
	}

	i = n = 0;

	for_each_sg(mhp->umem->sg_head.sgl, sg, mhp->umem->nmap, entry) {
		len = sg_dma_len(sg) >> shift;
		for (k = 0; k < len; ++k) {
			pages[i++] = cpu_to_be64(sg_dma_address(sg) +
					mhp->umem->page_size * k);
			if (i == PAGE_SIZE / sizeof *pages) {
				err = iwch_write_pbl(mhp, pages, i, n);
				if (err)
					goto pbl_done;
				n += i;
				i = 0;
			}
		}
	}
#if 0
	TAILQ_FOREACH(chunk, &mhp->umem->chunk_list, entry)
		for (j = 0; j < chunk->nmap; ++j) {
			len = sg_dma_len(&chunk->page_list[j]) >> shift;
			for (k = 0; k < len; ++k) {
				pages[i++] = htobe64(sg_dma_address(
					&chunk->page_list[j]) +
					mhp->umem->page_size * k);
				if (i == PAGE_SIZE / sizeof *pages) {
					err = iwch_write_pbl(mhp, pages, i, n);
					if (err)
						goto pbl_done;
					n += i;
					i = 0;
				}
			}
		}
#endif

	if (i)
		err = iwch_write_pbl(mhp, pages, i, n);
pbl_done:
	cxfree(pages);
	if (err)
		goto err_pbl;

	mhp->attr.pdid = php->pdid;
	mhp->attr.zbva = 0;
	mhp->attr.perms = iwch_ib_to_tpt_access(acc);
	mhp->attr.va_fbo = virt;
	mhp->attr.page_size = shift - 12;
	mhp->attr.len = (u32) length;
	
	err = iwch_register_mem(rhp, php, mhp, shift);
	if (err)
		goto err_pbl;

	if (udata && !t3a_device(rhp)) {
		uresp.pbl_addr = (mhp->attr.pbl_addr -
	                         rhp->rdev.rnic_info.pbl_base) >> 3;
		CTR2(KTR_IW_CXGB, "%s user resp pbl_addr 0x%x", __FUNCTION__,
		     uresp.pbl_addr);

		if (ib_copy_to_udata(udata, &uresp, sizeof (uresp))) {
			iwch_dereg_mr(&mhp->ibmr);
			err = EFAULT;
			goto err;
		}
	}

	return &mhp->ibmr;

err_pbl:
	iwch_free_pbl(mhp);

err:
	ib_umem_release(mhp->umem);
	cxfree(mhp);
	return ERR_PTR(-err);
}

static struct ib_mr *iwch_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct ib_phys_buf bl;
	u64 kva;
	struct ib_mr *ibmr;

	CTR2(KTR_IW_CXGB, "%s ib_pd %p", __FUNCTION__, pd);

	/*
	 * T3 only supports 32 bits of size.
	 */
	bl.size = 0xffffffff;
	bl.addr = 0;
	kva = 0;
	ibmr = iwch_register_phys_mem(pd, &bl, 1, acc, &kva);
	return ibmr;
}

static struct ib_mw *iwch_alloc_mw(struct ib_pd *pd, enum ib_mw_type type)
{
	struct iwch_dev *rhp;
	struct iwch_pd *php;
	struct iwch_mw *mhp;
	u32 mmid;
	u32 stag = 0;
	int ret;

	php = to_iwch_pd(pd);
	rhp = php->rhp;
	mhp = malloc(sizeof(*mhp), M_DEVBUF, M_ZERO|M_NOWAIT);
	if (!mhp)
		return ERR_PTR(-ENOMEM);
	ret = cxio_allocate_window(&rhp->rdev, &stag, php->pdid);
	if (ret) {
		cxfree(mhp);
		return ERR_PTR(-ret);
	}
	mhp->rhp = rhp;
	mhp->attr.pdid = php->pdid;
	mhp->attr.type = TPT_MW;
	mhp->attr.stag = stag;
	mmid = (stag) >> 8;
	mhp->ibmw.rkey = stag;
	if (insert_handle(rhp, &rhp->mmidr, mhp, mmid)) {
		cxio_deallocate_window(&rhp->rdev, mhp->attr.stag);
		cxfree(mhp);
		return ERR_PTR(-ENOMEM);
	}	
	CTR4(KTR_IW_CXGB, "%s mmid 0x%x mhp %p stag 0x%x", __FUNCTION__, mmid, mhp, stag);
	return &(mhp->ibmw);
}

static int iwch_dealloc_mw(struct ib_mw *mw)
{
	struct iwch_dev *rhp;
	struct iwch_mw *mhp;
	u32 mmid;

	mhp = to_iwch_mw(mw);
	rhp = mhp->rhp;
	mmid = (mw->rkey) >> 8;
	cxio_deallocate_window(&rhp->rdev, mhp->attr.stag);
	remove_handle(rhp, &rhp->mmidr, mmid);
	cxfree(mhp);
	CTR4(KTR_IW_CXGB, "%s ib_mw %p mmid 0x%x ptr %p", __FUNCTION__, mw, mmid, mhp);
	return 0;
}

static int iwch_destroy_qp(struct ib_qp *ib_qp)
{
	struct iwch_dev *rhp;
	struct iwch_qp *qhp;
	struct iwch_qp_attributes attrs;
	struct iwch_ucontext *ucontext;

	qhp = to_iwch_qp(ib_qp);
	rhp = qhp->rhp;

	attrs.next_state = IWCH_QP_STATE_ERROR;
	iwch_modify_qp(rhp, qhp, IWCH_QP_ATTR_NEXT_STATE, &attrs, 0);
	mtx_lock(&qhp->lock);
	if (qhp->ep)
		msleep(qhp, &qhp->lock, 0, "iwch_destroy_qp1", 0);
	mtx_unlock(&qhp->lock);

	remove_handle(rhp, &rhp->qpidr, qhp->wq.qpid);

	mtx_lock(&qhp->lock);
	if (--qhp->refcnt)
		msleep(qhp, &qhp->lock, 0, "iwch_destroy_qp2", 0);
	mtx_unlock(&qhp->lock);

	ucontext = ib_qp->uobject ? to_iwch_ucontext(ib_qp->uobject->context)
				  : NULL;
	cxio_destroy_qp(&rhp->rdev, &qhp->wq,
			ucontext ? &ucontext->uctx : &rhp->rdev.uctx);

	CTR4(KTR_IW_CXGB, "%s ib_qp %p qpid 0x%0x qhp %p", __FUNCTION__,
	     ib_qp, qhp->wq.qpid, qhp);
	cxfree(qhp);
	return 0;
}

static struct ib_qp *iwch_create_qp(struct ib_pd *pd,
			     struct ib_qp_init_attr *attrs,
			     struct ib_udata *udata)
{
	struct iwch_dev *rhp;
	struct iwch_qp *qhp;
	struct iwch_pd *php;
	struct iwch_cq *schp;
	struct iwch_cq *rchp;
	struct iwch_create_qp_resp uresp;
	int wqsize, sqsize, rqsize;
	struct iwch_ucontext *ucontext;

	CTR2(KTR_IW_CXGB, "%s ib_pd %p", __FUNCTION__, pd);
	if (attrs->qp_type != IB_QPT_RC)
		return ERR_PTR(-EINVAL);
	php = to_iwch_pd(pd);
	rhp = php->rhp;
	schp = get_chp(rhp, ((struct iwch_cq *) attrs->send_cq)->cq.cqid);
	rchp = get_chp(rhp, ((struct iwch_cq *) attrs->recv_cq)->cq.cqid);
	if (!schp || !rchp)
		return ERR_PTR(-EINVAL);

	/* The RQT size must be # of entries + 1 rounded up to a power of two */
	rqsize = roundup_pow_of_two(attrs->cap.max_recv_wr);
	if (rqsize == attrs->cap.max_recv_wr)
		rqsize = roundup_pow_of_two(attrs->cap.max_recv_wr+1);

	/* T3 doesn't support RQT depth < 16 */
	if (rqsize < 16)
		rqsize = 16;

	if (rqsize > T3_MAX_RQ_SIZE)
		return ERR_PTR(-EINVAL);

	if (attrs->cap.max_inline_data > T3_MAX_INLINE)
		return ERR_PTR(-EINVAL);

	/*
	 * NOTE: The SQ and total WQ sizes don't need to be
	 * a power of two.  However, all the code assumes
	 * they are. EG: Q_FREECNT() and friends.
	 */
	sqsize = roundup_pow_of_two(attrs->cap.max_send_wr);
	wqsize = roundup_pow_of_two(rqsize + sqsize);
	CTR4(KTR_IW_CXGB, "%s wqsize %d sqsize %d rqsize %d", __FUNCTION__,
	     wqsize, sqsize, rqsize);
	qhp = malloc(sizeof(*qhp), M_DEVBUF, M_ZERO|M_NOWAIT);
	if (!qhp)
		return ERR_PTR(-ENOMEM);
	qhp->wq.size_log2 = ilog2(wqsize);
	qhp->wq.rq_size_log2 = ilog2(rqsize);
	qhp->wq.sq_size_log2 = ilog2(sqsize);
	ucontext = pd->uobject ? to_iwch_ucontext(pd->uobject->context) : NULL;
	if (cxio_create_qp(&rhp->rdev, !udata, &qhp->wq,
			   ucontext ? &ucontext->uctx : &rhp->rdev.uctx)) {
		cxfree(qhp);
		return ERR_PTR(-ENOMEM);
	}

	attrs->cap.max_recv_wr = rqsize - 1;
	attrs->cap.max_send_wr = sqsize;
	attrs->cap.max_inline_data = T3_MAX_INLINE;

	qhp->rhp = rhp;
	qhp->attr.pd = php->pdid;
	qhp->attr.scq = ((struct iwch_cq *) attrs->send_cq)->cq.cqid;
	qhp->attr.rcq = ((struct iwch_cq *) attrs->recv_cq)->cq.cqid;
	qhp->attr.sq_num_entries = attrs->cap.max_send_wr;
	qhp->attr.rq_num_entries = attrs->cap.max_recv_wr;
	qhp->attr.sq_max_sges = attrs->cap.max_send_sge;
	qhp->attr.sq_max_sges_rdma_write = attrs->cap.max_send_sge;
	qhp->attr.rq_max_sges = attrs->cap.max_recv_sge;
	qhp->attr.state = IWCH_QP_STATE_IDLE;
	qhp->attr.next_state = IWCH_QP_STATE_IDLE;

	/*
	 * XXX - These don't get passed in from the openib user
	 * at create time.  The CM sets them via a QP modify.
	 * Need to fix...  I think the CM should
	 */
	qhp->attr.enable_rdma_read = 1;
	qhp->attr.enable_rdma_write = 1;
	qhp->attr.enable_bind = 1;
	qhp->attr.max_ord = 1;
	qhp->attr.max_ird = 1;

	mtx_init(&qhp->lock, "cxgb qp", NULL, MTX_DEF|MTX_DUPOK);
	qhp->refcnt = 1;

	if (insert_handle(rhp, &rhp->qpidr, qhp, qhp->wq.qpid)) {
		cxio_destroy_qp(&rhp->rdev, &qhp->wq,
			ucontext ? &ucontext->uctx : &rhp->rdev.uctx);
		cxfree(qhp);
		return ERR_PTR(-ENOMEM);
	}

	if (udata) {

		struct iwch_mm_entry *mm1, *mm2;

		mm1 = kmalloc(sizeof *mm1, M_NOWAIT);
		if (!mm1) {
			iwch_destroy_qp(&qhp->ibqp);
			return ERR_PTR(-ENOMEM);
		}

		mm2 = kmalloc(sizeof *mm2, M_NOWAIT);
		if (!mm2) {
			cxfree(mm1);
			iwch_destroy_qp(&qhp->ibqp);
			return ERR_PTR(-ENOMEM);
		}

		uresp.qpid = qhp->wq.qpid;
		uresp.size_log2 = qhp->wq.size_log2;
		uresp.sq_size_log2 = qhp->wq.sq_size_log2;
		uresp.rq_size_log2 = qhp->wq.rq_size_log2;
		mtx_lock(&ucontext->mmap_lock);
		uresp.key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		uresp.db_key = ucontext->key;
		ucontext->key += PAGE_SIZE;
		mtx_unlock(&ucontext->mmap_lock);
		if (ib_copy_to_udata(udata, &uresp, sizeof (uresp))) {
			cxfree(mm1);
			cxfree(mm2);
			iwch_destroy_qp(&qhp->ibqp);
			return ERR_PTR(-EFAULT);
		}
		mm1->key = uresp.key;
		mm1->addr = vtophys(qhp->wq.queue);
		mm1->len = PAGE_ALIGN(wqsize * sizeof (union t3_wr));
		insert_mmap(ucontext, mm1);
		mm2->key = uresp.db_key;
		mm2->addr = qhp->wq.udb & PAGE_MASK;
		mm2->len = PAGE_SIZE;
		insert_mmap(ucontext, mm2);
	}
	qhp->ibqp.qp_num = qhp->wq.qpid;
	callout_init(&(qhp->timer), 1);
	CTR6(KTR_IW_CXGB, "sq_num_entries %d, rq_num_entries %d "
	     "qpid 0x%0x qhp %p dma_addr 0x%llx size %d",
	     qhp->attr.sq_num_entries, qhp->attr.rq_num_entries,
	     qhp->wq.qpid, qhp, (unsigned long long) qhp->wq.dma_addr,
	     1 << qhp->wq.size_log2);
	return &qhp->ibqp;
}

static int iwch_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		      int attr_mask, struct ib_udata *udata)
{
	struct iwch_dev *rhp;
	struct iwch_qp *qhp;
	enum iwch_qp_attr_mask mask = 0;
	struct iwch_qp_attributes attrs;

	CTR2(KTR_IW_CXGB, "%s ib_qp %p", __FUNCTION__, ibqp);

	/* iwarp does not support the RTR state */
	if ((attr_mask & IB_QP_STATE) && (attr->qp_state == IB_QPS_RTR))
		attr_mask &= ~IB_QP_STATE;

	/* Make sure we still have something left to do */
	if (!attr_mask)
		return 0;

	memset(&attrs, 0, sizeof attrs);
	qhp = to_iwch_qp(ibqp);
	rhp = qhp->rhp;

	attrs.next_state = iwch_convert_state(attr->qp_state);
	attrs.enable_rdma_read = (attr->qp_access_flags &
			       IB_ACCESS_REMOTE_READ) ?  1 : 0;
	attrs.enable_rdma_write = (attr->qp_access_flags &
				IB_ACCESS_REMOTE_WRITE) ? 1 : 0;
	attrs.enable_bind = (attr->qp_access_flags & IB_ACCESS_MW_BIND) ? 1 : 0;


	mask |= (attr_mask & IB_QP_STATE) ? IWCH_QP_ATTR_NEXT_STATE : 0;
	mask |= (attr_mask & IB_QP_ACCESS_FLAGS) ?
			(IWCH_QP_ATTR_ENABLE_RDMA_READ |
			 IWCH_QP_ATTR_ENABLE_RDMA_WRITE |
			 IWCH_QP_ATTR_ENABLE_RDMA_BIND) : 0;

	return iwch_modify_qp(rhp, qhp, mask, &attrs, 0);
}

void iwch_qp_add_ref(struct ib_qp *qp)
{
	CTR2(KTR_IW_CXGB, "%s ib_qp %p", __FUNCTION__, qp);
	mtx_lock(&to_iwch_qp(qp)->lock);
	to_iwch_qp(qp)->refcnt++;
	mtx_unlock(&to_iwch_qp(qp)->lock);
}

void iwch_qp_rem_ref(struct ib_qp *qp)
{
	CTR2(KTR_IW_CXGB, "%s ib_qp %p", __FUNCTION__, qp);
	mtx_lock(&to_iwch_qp(qp)->lock);
	if (--to_iwch_qp(qp)->refcnt == 0)
	        wakeup(to_iwch_qp(qp));
	mtx_unlock(&to_iwch_qp(qp)->lock);
}

static struct ib_qp *iwch_get_qp(struct ib_device *dev, int qpn)
{
	CTR3(KTR_IW_CXGB, "%s ib_dev %p qpn 0x%x", __FUNCTION__, dev, qpn);
	return (struct ib_qp *)get_qhp(to_iwch_dev(dev), qpn);
}


static int iwch_query_pkey(struct ib_device *ibdev,
			   u8 port, u16 index, u16 * pkey)
{
	CTR2(KTR_IW_CXGB, "%s ibdev %p", __FUNCTION__, ibdev);
	*pkey = 0;
	return 0;
}

static int iwch_query_gid(struct ib_device *ibdev, u8 port,
			  int index, union ib_gid *gid)
{
	struct iwch_dev *dev;
	struct port_info *pi;
	struct adapter *sc;

	CTR5(KTR_IW_CXGB, "%s ibdev %p, port %d, index %d, gid %p",
	       __FUNCTION__, ibdev, port, index, gid);
	dev = to_iwch_dev(ibdev);
	sc = dev->rdev.adap;
	PANIC_IF(port == 0 || port > 2);
	pi = &sc->port[port - 1];
	memset(&(gid->raw[0]), 0, sizeof(gid->raw));
	memcpy(&(gid->raw[0]), pi->hw_addr, 6);
	return 0;
}

static int iwch_query_device(struct ib_device *ibdev,
			     struct ib_device_attr *props)
{
	struct iwch_dev *dev;
	struct adapter *sc;

	CTR2(KTR_IW_CXGB, "%s ibdev %p", __FUNCTION__, ibdev);

	dev = to_iwch_dev(ibdev);
	sc = dev->rdev.adap;
	memset(props, 0, sizeof *props);
	memcpy(&props->sys_image_guid, sc->port[0].hw_addr, 6);
	props->device_cap_flags = dev->device_cap_flags;
	props->page_size_cap = dev->attr.mem_pgsizes_bitmask;
	props->vendor_id = pci_get_vendor(sc->dev);
	props->vendor_part_id = pci_get_device(sc->dev);
	props->max_mr_size = dev->attr.max_mr_size;
	props->max_qp = dev->attr.max_qps;
	props->max_qp_wr = dev->attr.max_wrs;
	props->max_sge = dev->attr.max_sge_per_wr;
	props->max_sge_rd = 1;
	props->max_qp_rd_atom = dev->attr.max_rdma_reads_per_qp;
	props->max_qp_init_rd_atom = dev->attr.max_rdma_reads_per_qp;
	props->max_cq = dev->attr.max_cqs;
	props->max_cqe = dev->attr.max_cqes_per_cq;
	props->max_mr = dev->attr.max_mem_regs;
	props->max_pd = dev->attr.max_pds;
	props->local_ca_ack_delay = 0;

	return 0;
}

static int iwch_query_port(struct ib_device *ibdev,
			   u8 port, struct ib_port_attr *props)
{
	CTR2(KTR_IW_CXGB, "%s ibdev %p", __FUNCTION__, ibdev);
	memset(props, 0, sizeof(struct ib_port_attr));
	props->max_mtu = IB_MTU_4096;
	props->active_mtu = IB_MTU_2048;
	props->state = IB_PORT_ACTIVE;
	props->port_cap_flags =
	    IB_PORT_CM_SUP |
	    IB_PORT_SNMP_TUNNEL_SUP |
	    IB_PORT_REINIT_SUP |
	    IB_PORT_DEVICE_MGMT_SUP |
	    IB_PORT_VENDOR_CLASS_SUP | IB_PORT_BOOT_MGMT_SUP;
	props->gid_tbl_len = 1;
	props->pkey_tbl_len = 1;
	props->active_width = 2;
	props->active_speed = 2;
	props->max_msg_sz = -1;

	return 0;
}

int iwch_register_device(struct iwch_dev *dev)
{
	int ret;
	struct adapter *sc = dev->rdev.adap;

	CTR2(KTR_IW_CXGB, "%s iwch_dev %p", __FUNCTION__, dev);
	strlcpy(dev->ibdev.name, "cxgb3_%d", IB_DEVICE_NAME_MAX);
	memset(&dev->ibdev.node_guid, 0, sizeof(dev->ibdev.node_guid));
	memcpy(&dev->ibdev.node_guid, sc->port[0].hw_addr, 6);
	dev->device_cap_flags =
		(IB_DEVICE_LOCAL_DMA_LKEY |
		 IB_DEVICE_MEM_WINDOW);

	dev->ibdev.uverbs_cmd_mask =
	    (1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
	    (1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_REG_MR) |
	    (1ull << IB_USER_VERBS_CMD_DEREG_MR) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_QP) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
	    (1ull << IB_USER_VERBS_CMD_POLL_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_QP) |
	    (1ull << IB_USER_VERBS_CMD_POST_SEND) |
	    (1ull << IB_USER_VERBS_CMD_POST_RECV);
	dev->ibdev.node_type = RDMA_NODE_RNIC;
	memcpy(dev->ibdev.node_desc, IWCH_NODE_DESC, sizeof(IWCH_NODE_DESC));
	dev->ibdev.phys_port_cnt = sc->params.nports;
	dev->ibdev.num_comp_vectors = 1;
	dev->ibdev.dma_device = NULL;
	dev->ibdev.query_device = iwch_query_device;
	dev->ibdev.query_port = iwch_query_port;
	dev->ibdev.modify_port = iwch_modify_port;
	dev->ibdev.query_pkey = iwch_query_pkey;
	dev->ibdev.query_gid = iwch_query_gid;
	dev->ibdev.alloc_ucontext = iwch_alloc_ucontext;
	dev->ibdev.dealloc_ucontext = iwch_dealloc_ucontext;
	dev->ibdev.mmap = iwch_mmap;
	dev->ibdev.alloc_pd = iwch_allocate_pd;
	dev->ibdev.dealloc_pd = iwch_deallocate_pd;
	dev->ibdev.create_ah = iwch_ah_create;
	dev->ibdev.destroy_ah = iwch_ah_destroy;
	dev->ibdev.create_qp = iwch_create_qp;
	dev->ibdev.modify_qp = iwch_ib_modify_qp;
	dev->ibdev.destroy_qp = iwch_destroy_qp;
	dev->ibdev.create_cq = iwch_create_cq;
	dev->ibdev.destroy_cq = iwch_destroy_cq;
	dev->ibdev.resize_cq = iwch_resize_cq;
	dev->ibdev.poll_cq = iwch_poll_cq;
	dev->ibdev.get_dma_mr = iwch_get_dma_mr;
	dev->ibdev.reg_phys_mr = iwch_register_phys_mem;
	dev->ibdev.rereg_phys_mr = iwch_reregister_phys_mem;
	dev->ibdev.reg_user_mr = iwch_reg_user_mr;
	dev->ibdev.dereg_mr = iwch_dereg_mr;
	dev->ibdev.alloc_mw = iwch_alloc_mw;
	dev->ibdev.bind_mw = iwch_bind_mw;
	dev->ibdev.dealloc_mw = iwch_dealloc_mw;

	dev->ibdev.attach_mcast = iwch_multicast_attach;
	dev->ibdev.detach_mcast = iwch_multicast_detach;
	dev->ibdev.process_mad = iwch_process_mad;

	dev->ibdev.req_notify_cq = iwch_arm_cq;
	dev->ibdev.post_send = iwch_post_send;
	dev->ibdev.post_recv = iwch_post_receive;
	dev->ibdev.uverbs_abi_ver = IWCH_UVERBS_ABI_VERSION;

	dev->ibdev.iwcm =
	    kmalloc(sizeof(struct iw_cm_verbs), M_NOWAIT);
	if (!dev->ibdev.iwcm)
		return (ENOMEM);

	dev->ibdev.iwcm->connect = iwch_connect;
	dev->ibdev.iwcm->accept = iwch_accept_cr;
	dev->ibdev.iwcm->reject = iwch_reject_cr;
	dev->ibdev.iwcm->create_listen_ep = iwch_create_listen_ep;
	dev->ibdev.iwcm->destroy_listen_ep = iwch_destroy_listen_ep;
	dev->ibdev.iwcm->newconn = process_newconn;
	dev->ibdev.iwcm->add_ref = iwch_qp_add_ref;
	dev->ibdev.iwcm->rem_ref = iwch_qp_rem_ref;
	dev->ibdev.iwcm->get_qp = iwch_get_qp;

	ret = ib_register_device(&dev->ibdev, NULL);
	if (ret)
		goto bail1;

	return (0);

bail1:
	cxfree(dev->ibdev.iwcm);
	return (ret);
}

void iwch_unregister_device(struct iwch_dev *dev)
{

	ib_unregister_device(&dev->ibdev);
	cxfree(dev->ibdev.iwcm);
	return;
}
#endif
