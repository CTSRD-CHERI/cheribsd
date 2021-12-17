/*
 * Copyright (C) 2018 Alexandru Elisei <alexandru.elisei@gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/smp.h>
#include <sys/bitstring.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <dev/ofw/openfirm.h>

#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/cpufunc.h>
#include <machine/cpu.h>
#include <machine/machdep.h>
#include <machine/param.h>
#include <machine/pmap.h>
#include <machine/vmparam.h>
#include <machine/intr.h>
#include <machine/vmm.h>
#include <machine/vmm_instruction_emul.h>

#include <arm/arm/gic_common.h>
#include <arm64/arm64/gic_v3_reg.h>
#include <arm64/arm64/gic_v3_var.h>

#include <arm64/vmm/hyp.h>
#include <arm64/vmm/mmu.h>
#include <arm64/vmm/arm64.h>

#include "vgic_v3.h"
#include "vgic_v3_reg.h"

MALLOC_DEFINE(M_VGIC_V3, "ARM VMM VGIC V3", "ARM VMM VGIC V3");

static bool have_vgic = false;

struct vgic_v3_virt_features {
	uint8_t min_prio;
	size_t ich_lr_num;
	size_t ich_apr_num;
};

/* How many IRQs we support (SGIs + PPIs + SPIs). Not including LPIs */
#define	VGIC_NIRQS	1023
/* Pretend to be an Arm design */
#define	VGIC_IIDR	0x43b

typedef void (register_read)(struct hyp *, int, u_int, uint64_t *, void *);
typedef void (register_write)(struct hyp *, int, u_int, u_int, u_int, uint64_t,
    void *);

#define	VGIC_8_BIT	(1 << 0)
/* (1 << 1) is reserved for 16 bit accesses */
#define	VGIC_32_BIT	(1 << 2)
#define	VGIC_64_BIT	(1 << 3)

struct vgic_register {
	u_int start;	/* Start within a memory region */
	u_int end;
	u_int size;
	u_int flags;
	register_read *read;
	register_write *write;
};

#define	VGIC_REGISTER_RANGE(reg_start, reg_end, reg_size, reg_flags, readf, \
    writef)								\
{									\
	.start = (reg_start),						\
	.end = (reg_end),						\
	.size = (reg_size),						\
	.flags = (reg_flags),						\
	.read = (readf),						\
	.write = (writef),						\
}

#define	VGIC_REGISTER_RANGE_RAZ_WI(reg_start, reg_end, reg_size, reg_flags) \
	VGIC_REGISTER_RANGE(reg_start, reg_end, reg_size, reg_flags,	\
	    gic_zero_read, gic_ignore_write)

#define	VGIC_REGISTER(start_addr, reg_size, reg_flags, readf, writef)	\
	VGIC_REGISTER_RANGE(start_addr, (start_addr) + (reg_size),	\
	    reg_size, reg_flags, readf, writef)

#define	VGIC_REGISTER_RAZ_WI(start_addr, reg_size, reg_flags)		\
	VGIC_REGISTER_RANGE_RAZ_WI(start_addr,				\
	    (start_addr) + (reg_size), reg_size, reg_flags)

static register_read gic_pidr2_read;
static register_read gic_zero_read;
static register_write gic_ignore_write;

/* GICD_CTLR */
static register_read dist_ctlr_read;
static register_write dist_ctlr_write;
/* GICD_TYPER */
static register_read dist_typer_read;
/* GICD_IIDR */
static register_read dist_iidr_read;
/* GICD_STATUSR - RAZ/WI as we don't report errors (yet) */
/* GICD_SETSPI_NSR & GICD_CLRSPI_NSR */
static register_write dist_setclrspi_nsr_write;
/* GICD_SETSPI_SR - RAZ/WI */
/* GICD_CLRSPI_SR - RAZ/WI */
/* GICD_IGROUPR - RAZ/WI as GICD_CTLR.ARE == 1 */
/* GICD_ISENABLER */
static register_read dist_isenabler_read;
static register_write dist_isenabler_write;
/* GICD_ICENABLER */
static register_read dist_icenabler_read;
static register_write dist_icenabler_write;
/* GICD_ISPENDR */
static register_read dist_ispendr_read;
static register_write dist_ispendr_write;
/* GICD_ICPENDR */
static register_read dist_icpendr_read;
static register_write dist_icpendr_write;
/* GICD_ISACTIVER */
static register_read dist_isactiver_read;
static register_write dist_isactiver_write;
/* GICD_ICACTIVER */
static register_read dist_icactiver_read;
static register_write dist_icactiver_write;
/* GICD_IPRIORITYR */
static register_read dist_ipriorityr_read;
static register_write dist_ipriorityr_write;
/* GICD_ITARGETSR - RAZ/WI as GICD_CTLR.ARE == 1 */
/* GICD_ICFGR */
static register_read dist_icfgr_read;
static register_write dist_icfgr_write;
/* GICD_IGRPMODR - RAZ/WI from non-secure mode */
/* GICD_NSACR - RAZ/WI from non-secure mode */
/* GICD_SGIR - RAZ/WI as GICD_CTLR.ARE == 1 */
/* GICD_CPENDSGIR - RAZ/WI as GICD_CTLR.ARE == 1 */
/* GICD_SPENDSGIR - RAZ/WI as GICD_CTLR.ARE == 1 */
/* GICD_IROUTER */
static register_read dist_irouter_read;
static register_write dist_irouter_write;

static struct vgic_register dist_registers[] = {
	VGIC_REGISTER(GICD_CTLR, 4, VGIC_32_BIT, dist_ctlr_read,
	    dist_ctlr_write),
	VGIC_REGISTER(GICD_TYPER, 4, VGIC_32_BIT, dist_typer_read,
	    gic_ignore_write),
	VGIC_REGISTER(GICD_IIDR, 4, VGIC_32_BIT, dist_iidr_read,
	    gic_ignore_write),
	VGIC_REGISTER_RAZ_WI(GICD_STATUSR, 4, VGIC_32_BIT),
	VGIC_REGISTER(GICD_SETSPI_NSR, 4, VGIC_32_BIT, gic_zero_read,
	    dist_setclrspi_nsr_write),
	VGIC_REGISTER(GICD_CLRSPI_NSR, 4, VGIC_32_BIT, gic_zero_read,
	    dist_setclrspi_nsr_write),
	VGIC_REGISTER_RAZ_WI(GICD_SETSPI_SR, 4, VGIC_32_BIT),
	VGIC_REGISTER_RAZ_WI(GICD_CLRSPI_SR, 4, VGIC_32_BIT),
	VGIC_REGISTER_RANGE_RAZ_WI(GICD_IGROUPR(0), GICD_IGROUPR(1024), 4,
	    VGIC_32_BIT),

	VGIC_REGISTER_RAZ_WI(GICD_ISENABLER(0), 4, VGIC_32_BIT),
	VGIC_REGISTER_RANGE(GICD_ISENABLER(32), GICD_ISENABLER(1024), 4,
	    VGIC_32_BIT, dist_isenabler_read, dist_isenabler_write),

	VGIC_REGISTER_RAZ_WI(GICD_ICENABLER(0), 4, VGIC_32_BIT),
	VGIC_REGISTER_RANGE(GICD_ICENABLER(32), GICD_ICENABLER(1024), 4,
	    VGIC_32_BIT, dist_icenabler_read, dist_icenabler_write),

	VGIC_REGISTER_RAZ_WI(GICD_ISPENDR(0), 4, VGIC_32_BIT),
	VGIC_REGISTER_RANGE(GICD_ISPENDR(32), GICD_ISPENDR(1024), 4,
	    VGIC_32_BIT, dist_ispendr_read, dist_ispendr_write),

	VGIC_REGISTER_RAZ_WI(GICD_ICPENDR(0), 4, VGIC_32_BIT),
	VGIC_REGISTER_RANGE(GICD_ICPENDR(32), GICD_ICPENDR(1024), 4,
	    VGIC_32_BIT, dist_icpendr_read, dist_icpendr_write),

	VGIC_REGISTER_RAZ_WI(GICD_ISACTIVER(0), 4, VGIC_32_BIT),
	VGIC_REGISTER_RANGE(GICD_ISACTIVER(32), GICD_ISACTIVER(1024), 4,
	    VGIC_32_BIT, dist_isactiver_read, dist_isactiver_write),

	VGIC_REGISTER_RAZ_WI(GICD_ICACTIVER(0), 4, VGIC_32_BIT),
	VGIC_REGISTER_RANGE(GICD_ICACTIVER(32), GICD_ICACTIVER(1024), 4,
	    VGIC_32_BIT, dist_icactiver_read, dist_icactiver_write),

	VGIC_REGISTER_RANGE_RAZ_WI(GICD_IPRIORITYR(0), GICD_IPRIORITYR(32), 4,
	    VGIC_32_BIT | VGIC_8_BIT),
	VGIC_REGISTER_RANGE(GICD_IPRIORITYR(32), GICD_IPRIORITYR(1024), 4,
	    VGIC_32_BIT | VGIC_8_BIT, dist_ipriorityr_read,
	    dist_ipriorityr_write),

	VGIC_REGISTER_RANGE_RAZ_WI(GICD_ITARGETSR(0), GICD_ITARGETSR(1024), 4,
	    VGIC_32_BIT | VGIC_8_BIT),

	VGIC_REGISTER_RANGE_RAZ_WI(GICD_ICFGR(0), GICD_ICFGR(32), 4,
	    VGIC_32_BIT),
	VGIC_REGISTER_RANGE(GICD_ICFGR(32), GICD_ICFGR(1024), 4,
	    VGIC_32_BIT, dist_icfgr_read, dist_icfgr_write),
/*
	VGIC_REGISTER_RANGE(GICD_IGRPMODR(0), GICD_IGRPMODR(1024), 4,
	    VGIC_32_BIT, dist_igrpmodr_read, dist_igrpmodr_write),
	VGIC_REGISTER_RANGE(GICD_NSACR(0), GICD_NSACR(1024), 4,
	    VGIC_32_BIT, dist_nsacr_read, dist_nsacr_write),
*/
	VGIC_REGISTER_RAZ_WI(GICD_SGIR, 4, VGIC_32_BIT),
/*
	VGIC_REGISTER_RANGE(GICD_CPENDSGIR(0), GICD_CPENDSGIR(1024), 4,
	    VGIC_32_BIT | VGIC_8_BIT, dist_cpendsgir_read,
	    dist_cpendsgir_write),
	VGIC_REGISTER_RANGE(GICD_SPENDSGIR(0), GICD_SPENDSGIR(1024), 4,
	    VGIC_32_BIT | VGIC_8_BIT, dist_spendsgir_read,
	    dist_spendsgir_write),
*/
	VGIC_REGISTER_RANGE(GICD_IROUTER(32), GICD_IROUTER(1024), 8,
	    VGIC_64_BIT | VGIC_32_BIT, dist_irouter_read, dist_irouter_write),

	VGIC_REGISTER_RANGE_RAZ_WI(GICD_PIDR4, GICD_PIDR2, 4, VGIC_32_BIT),
	VGIC_REGISTER(GICD_PIDR2, 4, VGIC_32_BIT, gic_pidr2_read,
	    gic_ignore_write),
	VGIC_REGISTER_RANGE_RAZ_WI(GICD_PIDR2 + 4, GICD_SIZE, 4, VGIC_32_BIT),
};

/* GICR_CTLR - Ignore writes as no bits can be set */
static register_read redist_ctlr_read;
/* GICR_IIDR */
static register_read redist_iidr_read;
/* GICR_TYPER */
static register_read redist_typer_read;
/* GICR_STATUSR - RAZ/WI as we don't report errors (yet) */
/* GICR_WAKER - RAZ/WI from non-secure mode */
/* GICR_SETLPIR - RAZ/WI as no LPIs are supported */
/* GICR_CLRLPIR - RAZ/WI as no LPIs are supported */
/* GICR_PROPBASER */
static register_read redist_propbaser_read;
static register_write redist_propbaser_write;
/* GICR_PENDBASER */
static register_read redist_pendbaser_read;
static register_write redist_pendbaser_write;
/* GICR_INVLPIR - RAZ/WI as no LPIs are supported */
/* GICR_INVALLR - RAZ/WI as no LPIs are supported */
/* GICR_SYNCR - RAZ/WI as no LPIs are supported */

static struct vgic_register redist_rd_registers[] = {
	VGIC_REGISTER(GICR_CTLR, 4, VGIC_32_BIT, redist_ctlr_read,
	    gic_ignore_write),
	VGIC_REGISTER(GICR_IIDR, 4, VGIC_32_BIT, redist_iidr_read,
	    gic_ignore_write),
	VGIC_REGISTER(GICR_TYPER, 8, VGIC_64_BIT | VGIC_32_BIT,
	    redist_typer_read, gic_ignore_write),
	VGIC_REGISTER_RAZ_WI(GICR_STATUSR, 4, VGIC_32_BIT),
	VGIC_REGISTER_RAZ_WI(GICR_WAKER, 4, VGIC_32_BIT),
	VGIC_REGISTER_RAZ_WI(GICR_SETLPIR, 8, VGIC_64_BIT | VGIC_32_BIT),
	VGIC_REGISTER_RAZ_WI(GICR_CLRLPIR, 8, VGIC_64_BIT | VGIC_32_BIT),
	VGIC_REGISTER(GICR_PROPBASER, 8, VGIC_64_BIT | VGIC_32_BIT,
	    redist_propbaser_read, redist_propbaser_write),
	VGIC_REGISTER(GICR_PENDBASER, 8, VGIC_64_BIT | VGIC_32_BIT,
	    redist_pendbaser_read, redist_pendbaser_write),
	VGIC_REGISTER_RAZ_WI(GICR_INVLPIR, 8, VGIC_64_BIT | VGIC_32_BIT),
	VGIC_REGISTER_RAZ_WI(GICR_INVALLR, 8, VGIC_64_BIT | VGIC_32_BIT),
	VGIC_REGISTER_RAZ_WI(GICR_SYNCR, 4, VGIC_32_BIT),

	/* These are identical to the dist registers */
	VGIC_REGISTER_RANGE_RAZ_WI(GICD_PIDR4, GICD_PIDR2, 4, VGIC_32_BIT),
	VGIC_REGISTER(GICD_PIDR2, 4, VGIC_32_BIT, gic_pidr2_read,
	    gic_ignore_write),
	VGIC_REGISTER_RANGE_RAZ_WI(GICD_PIDR2 + 4, GICD_SIZE, 4,
	    VGIC_32_BIT),
};

/* GICR_IGROUPR0 - RAZ/WI from non-secure mode */
/* GICR_ISENABLER0 */
static register_read redist_ienabler0_read;
static register_write redist_isenabler0_write;
/* GICR_ICENABLER0 */
static register_write redist_icenabler0_write;
/* GICR_ISPENDR0 */
static register_read redist_ipendr0_read;
static register_write redist_ispendr0_write;
/* GICR_ICPENDR0 */
static register_write redist_icpendr0_write;
/* GICR_ISACTIVER0 */
static register_read redist_iactiver0_read;
static register_write redist_isactiver0_write;
/* GICR_ICACTIVER0 */
static register_write redist_icactiver0_write;
/* GICR_IPRIORITYR */
static register_read redist_ipriorityr_read;
static register_write redist_ipriorityr_write;
/* GICR_ICFGR0 - RAZ/WI from non-secure mode */
/* GICR_ICFGR1 */
static register_read redist_icfgr1_read;
static register_write redist_icfgr1_write;
/* GICR_IGRPMODR0 - RAZ/WI from non-secure mode */
/* GICR_NSCAR - RAZ/WI from non-secure mode */

static struct vgic_register redist_sgi_registers[] = {
	VGIC_REGISTER_RAZ_WI(GICR_IGROUPR0, 4, VGIC_32_BIT),
	VGIC_REGISTER(GICR_ISENABLER0, 4, VGIC_32_BIT, redist_ienabler0_read,
	    redist_isenabler0_write),
	VGIC_REGISTER(GICR_ICENABLER0, 4, VGIC_32_BIT, redist_ienabler0_read,
	    redist_icenabler0_write),
	VGIC_REGISTER(GICR_ISPENDR0, 4, VGIC_32_BIT, redist_ipendr0_read,
	    redist_ispendr0_write),
	VGIC_REGISTER(GICR_ICPENDR0, 4, VGIC_32_BIT, redist_ipendr0_read,
	    redist_icpendr0_write),
	VGIC_REGISTER(GICR_ISACTIVER0, 4, VGIC_32_BIT, redist_iactiver0_read,
	    redist_isactiver0_write),
	VGIC_REGISTER(GICR_ICACTIVER0, 4, VGIC_32_BIT, redist_iactiver0_read,
	    redist_icactiver0_write),
	VGIC_REGISTER_RANGE(GICR_IPRIORITYR(0), GICR_IPRIORITYR(32), 4,
	    VGIC_32_BIT | VGIC_8_BIT, redist_ipriorityr_read,
	    redist_ipriorityr_write),
	VGIC_REGISTER_RAZ_WI(GICR_ICFGR0, 4, VGIC_32_BIT),
	VGIC_REGISTER(GICR_ICFGR1, 4, VGIC_32_BIT, redist_icfgr1_read,
	    redist_icfgr1_write),
	VGIC_REGISTER_RAZ_WI(GICR_IGRPMODR0, 4, VGIC_32_BIT),
	VGIC_REGISTER_RAZ_WI(GICR_NSACR, 4, VGIC_32_BIT),
};

static struct vgic_v3_virt_features virt_features;

static struct vgic_v3_irq *vgic_v3_get_irq(struct hyp *, int, uint32_t);
static void vgic_v3_release_irq(struct vgic_v3_irq *);

void
vgic_v3_vminit(struct hyp *hyp)
{
	struct vgic_v3_dist *dist = &hyp->vgic_dist;

	/*
	 * Configure the Distributor control register. The register resets to an
	 * architecturally UNKNOWN value, so we reset to 0 to disable all
	 * functionality controlled by the register.
	 *
	 * The exception is GICD_CTLR.DS, which is RA0/WI when the Distributor
	 * supports one security state (ARM GIC Architecture Specification for
	 * GICv3 and GICv4, p. 4-464)
	 */
	dist->gicd_ctlr = 0;

	mtx_init(&dist->dist_mtx, "VGICv3 Distributor lock", NULL, MTX_SPIN);
}

void
vgic_v3_cpuinit(struct hypctx *hypctx, bool last_vcpu)
{
	struct vgic_v3_cpu_if *cpu_if = &hypctx->vgic_cpu_if;
	struct vgic_v3_redist *redist = &hypctx->vgic_redist;
	struct vgic_v3_irq *irq;
	uint64_t aff, vmpidr_el2;
	int i, irqid;

	vmpidr_el2 = hypctx->vmpidr_el2;
	KASSERT(vmpidr_el2 != 0,
	    ("Trying to init this CPU's vGIC before the vCPU"));
	/*
	 * Get affinity for the current CPU. The guest CPU affinity is taken
	 * from VMPIDR_EL2. The Redistributor corresponding to this CPU is
	 * the Redistributor with the same affinity from GICR_TYPER.
	 */
	aff = (CPU_AFF3(vmpidr_el2) << 24) | (CPU_AFF2(vmpidr_el2) << 16) |
	    (CPU_AFF1(vmpidr_el2) << 8) | CPU_AFF0(vmpidr_el2);

	/* Set up GICR_TYPER. */
	redist->gicr_typer = aff << GICR_TYPER_AFF_SHIFT;
	/* Set the vcpu as the processsor ID */
	redist->gicr_typer |= hypctx->vcpu << GICR_TYPER_CPUNUM_SHIFT;

	if (last_vcpu)
		/* Mark the last Redistributor */
		redist->gicr_typer |= GICR_TYPER_LAST;

	redist->gicr_propbaser =
	    (GICR_PROPBASER_SHARE_OS << GICR_PROPBASER_SHARE_SHIFT) |
	    (GICR_PROPBASER_CACHE_NIWAWB << GICR_PROPBASER_CACHE_SHIFT);
	redist->gicr_pendbaser =
	    (GICR_PENDBASER_SHARE_OS << GICR_PENDBASER_SHARE_SHIFT) |
	    (GICR_PENDBASER_CACHE_NIWAWB << GICR_PENDBASER_CACHE_SHIFT);

	/* TODO: We need a call to mtx_destroy */
	mtx_init(&cpu_if->lr_mtx, "VGICv3 ICH_LR_EL2 lock", NULL, MTX_SPIN);

	/* Set the SGI and PPI state */
	for (irqid = 0; irqid < VGIC_PRV_I_NUM; irqid++) {
		irq = &cpu_if->private_irqs[irqid];

		/* TODO: We need a call to mtx_destroy */
		mtx_init(&irq->irq_spinmtx, "VGIC IRQ spinlock", NULL,
		    MTX_SPIN);
		irq->irq = irqid;
		irq->mpidr = hypctx->vmpidr_el2 & GICD_AFF;
		if (irqid < VGIC_SGI_NUM) {
			/* SGIs */
			irq->enabled = true;
			irq->config = VGIC_CONFIG_EDGE;
		} else {
			/* PPIs */
			irq->config = VGIC_CONFIG_LEVEL;
		}
		irq->priority = 0;
	}

	/*
	 * Configure the Interrupt Controller Hyp Control Register.
	 *
	 * ICH_HCR_EL2_En: enable virtual CPU interface.
	 *
	 * Maintenance interrupts are disabled.
	 */
	cpu_if->ich_hcr_el2 = ICH_HCR_EL2_En;

	/*
	 * Configure the Interrupt Controller Virtual Machine Control Register.
	 *
	 * ICH_VMCR_EL2_VPMR: lowest priority mask for the VCPU interface
	 * ICH_VMCR_EL2_VBPR1_NO_PREEMPTION: disable interrupt preemption for
	 * Group 1 interrupts
	 * ICH_VMCR_EL2_VBPR0_NO_PREEMPTION: disable interrupt preemption for
	 * Group 0 interrupts
	 * ~ICH_VMCR_EL2_VEOIM: writes to EOI registers perform priority drop
	 * and interrupt deactivation.
	 * ICH_VMCR_EL2_VENG0: virtual Group 0 interrupts enabled.
	 * ICH_VMCR_EL2_VENG1: virtual Group 1 interrupts enabled.
	 */
	cpu_if->ich_vmcr_el2 = \
	    (virt_features.min_prio << ICH_VMCR_EL2_VPMR_SHIFT) | \
	    ICH_VMCR_EL2_VBPR1_NO_PREEMPTION | ICH_VMCR_EL2_VBPR0_NO_PREEMPTION;
	cpu_if->ich_vmcr_el2 &= ~ICH_VMCR_EL2_VEOIM;
	cpu_if->ich_vmcr_el2 |= ICH_VMCR_EL2_VENG0 | ICH_VMCR_EL2_VENG1;

	cpu_if->ich_lr_num = virt_features.ich_lr_num;
	for (i = 0; i < cpu_if->ich_lr_num; i++)
		cpu_if->ich_lr_el2[i] = 0UL;
	cpu_if->ich_lr_used = 0;
	TAILQ_INIT(&cpu_if->irq_act_pend);

	cpu_if->ich_ap0r_num = virt_features.ich_apr_num;
	cpu_if->ich_ap1r_num = virt_features.ich_apr_num;
}

void
vgic_v3_cpucleanup(struct hypctx *hypctx)
{
	struct vgic_v3_cpu_if *cpu_if;
	struct vgic_v3_irq *irq;
	int irqid;

	cpu_if = &hypctx->vgic_cpu_if;
	for (irqid = 0; irqid < VGIC_PRV_I_NUM; irqid++) {
		irq = &cpu_if->private_irqs[irqid];
		mtx_destroy(&irq->irq_spinmtx);
	}

	mtx_destroy(&cpu_if->lr_mtx);
}

void
vgic_v3_vmcleanup(struct hyp *hyp)
{
	struct vgic_v3_dist *dist = &hyp->vgic_dist;

	mtx_destroy(&dist->dist_mtx);
}

static bool
vgic_v3_irq_pending(struct vgic_v3_irq *irq)
{
	if ((irq->config & VGIC_CONFIG_MASK) == VGIC_CONFIG_LEVEL) {
		return (irq->pending || irq->level);
	} else {
		return (irq->pending);
	}
}

static bool
vgic_v3_queue_irq(struct hyp *hyp, struct vgic_v3_cpu_if *cpu_if,
    int vcpuid, struct vgic_v3_irq *irq)
{
	MPASS(vcpuid >= 0);
	MPASS(vcpuid < VM_MAXCPU);

	mtx_assert(&cpu_if->lr_mtx, MA_OWNED);
	mtx_assert(&irq->irq_spinmtx, MA_OWNED);

	/* No need to queue the IRQ */
	if (!irq->level && !irq->pending)
		return (false);

	if (!irq->on_aplist) {
		irq->on_aplist = true;
		TAILQ_INSERT_TAIL(&cpu_if->irq_act_pend, irq, act_pend_list);
	}
	return (true);
}


static uint64_t
gic_reg_value_64(uint64_t field, uint64_t val, u_int offset, u_int size)
{
	uint32_t mask;

	if (offset != 0 || size != 8) {
		mask = ((1ul << (size * 8)) - 1) << (offset * 8);
		/* Shift the new bits to the correct place */
		val <<= (offset * 8);
		/* Keep only the interesting bits */
		val &= mask;
		/* Add the bits we are keeping from the old value */
		val |= field & ~mask;
	}

	return (val);
}

static void
gic_pidr2_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	*rval = GICR_PIDR2_ARCH_GICv3 << GICR_PIDR2_ARCH_SHIFT;
}

/* Common read-only/write-ignored helpers */
static void
gic_zero_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	*rval = 0;
}

static void
gic_ignore_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	/* Nothing to do */
}

static uint64_t
read_enabler(struct hyp *hyp, int vcpuid, int n)
{
	struct vgic_v3_irq *irq;
	uint64_t ret;
	uint32_t irq_base;
	int i;

	ret = 0;
	irq_base = n * 32;
	for (i = 0; i < 32; i++) {
		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		if (!irq->enabled)
			ret |= 1u << i;
		vgic_v3_release_irq(irq);
	}

	return (ret);
}

static void
write_enabler(struct hyp *hyp, int vcpuid, int n, bool set, uint64_t val)
{
	struct vgic_v3_irq *irq;
	uint32_t irq_base;
	int i;

	irq_base = n * 32;
	for (i = 0; i < 32; i++) {
		/* We only change interrupts when the appropriate bit is set */
		if ((val & (1u << i)) == 0)
			continue;

		/* Find the interrupt this bit represents */
		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		irq->enabled = set;
		vgic_v3_release_irq(irq);
	}
}

static uint64_t
read_pendr(struct hyp *hyp, int vcpuid, int n)
{
	struct vgic_v3_irq *irq;
	uint64_t ret;
	uint32_t irq_base;
	int i;

	ret = 0;
	irq_base = n * 32;
	for (i = 0; i < 32; i++) {
		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		if (vgic_v3_irq_pending(irq))
			ret |= 1u << i;
		vgic_v3_release_irq(irq);
	}

	return (ret);
}

static uint64_t
write_pendr(struct hyp *hyp, int vcpuid, int n, bool set, uint64_t val)
{
	struct vgic_v3_cpu_if *cpu_if;
	struct vgic_v3_irq *irq;
	uint64_t ret;
	uint32_t irq_base;
	int mpidr, i;
	bool notify;

	ret = 0;
	irq_base = n * 32;
	for (i = 0; i < 32; i++) {
		/* We only change interrupts when the appropriate bit is set */
		if ((val & (1u << i)) == 0)
			continue;

		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		/*
		 * TODO: The target CPU could have changed, we need to know
		 * on which CPU the interrupt is pending.
		 */
		mpidr = irq->mpidr;
		cpu_if = &hyp->ctx[mpidr].vgic_cpu_if;
		notify = false;

		if (!set) {
			/* pending -> not pending */
			irq->pending = false;
		} else {
			irq->pending = true;
			mtx_lock_spin(&cpu_if->lr_mtx);
			notify = vgic_v3_queue_irq(hyp, cpu_if, mpidr, irq);
			mtx_unlock_spin(&cpu_if->lr_mtx);
		}
		vgic_v3_release_irq(irq);

		if (notify)
			vcpu_notify_event(hyp->vm, mpidr, false);
	}

	return (ret);
}

static uint64_t
read_activer(struct hyp *hyp, int vcpuid, int n)
{
	struct vgic_v3_irq *irq;
	uint64_t ret;
	uint32_t irq_base;
	int i;

	ret = 0;
	irq_base = n * 32;
	for (i = 0; i < 32; i++) {
		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		if (irq->active)
			ret |= 1u << i;
		vgic_v3_release_irq(irq);
	}

	return (ret);
}

static void
write_activer(struct hyp *hyp, int vcpuid, u_int n, bool set, uint64_t val)
{
	struct vgic_v3_cpu_if *cpu_if;
	struct vgic_v3_irq *irq;
	uint32_t irq_base;
	int mpidr, i;
	bool notify;

	irq_base = n * 32;
	for (i = 0; i < 32; i++) {
		/* We only change interrupts when the appropriate bit is set */
		if ((val & (1u << i)) == 0)
			continue;

		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		/*
		 * TODO: The target CPU could have changed, we need to know
		 * on which CPU the interrupt is pending.
		 */
		mpidr = irq->mpidr;
		cpu_if = &hyp->ctx[mpidr].vgic_cpu_if;
		notify = false;

		if (!set) {
			/* active -> not active */
			irq->active = false;
		} else {
			/* not active -> active */
			irq->active = true;
			mtx_lock_spin(&cpu_if->lr_mtx);
			notify = vgic_v3_queue_irq(hyp, cpu_if, mpidr, irq);
			mtx_unlock_spin(&cpu_if->lr_mtx);
		}
		vgic_v3_release_irq(irq);

		if (notify)
			vcpu_notify_event(hyp->vm, mpidr, false);
	}
}

static uint64_t
read_priorityr(struct hyp *hyp, int vcpuid, int n)
{
	struct vgic_v3_irq *irq;
	uint64_t ret;
	uint32_t irq_base;
	int i;

	ret = 0;
	irq_base = n * 4;
	for (i = 0; i < 4; i++) {
		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		ret |= ((uint64_t)irq->priority) << (i * 8);
		vgic_v3_release_irq(irq);
	}

	return (ret);
}

static void
write_priorityr(struct hyp *hyp, int vcpuid, u_int irq_base, u_int size,
    uint64_t val)
{
	struct vgic_v3_irq *irq;
	int i;

	for (i = 0; i < size; i++) {
		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		/* Set the priority. We support 32 priority steps (5 bits) */
		irq->priority = (val >> (i * 8)) & 0xf8;
		vgic_v3_release_irq(irq);
	}
}

static uint64_t
read_config(struct hyp *hyp, int vcpuid, int n)
{
	struct vgic_v3_irq *irq;
	uint64_t ret;
	uint32_t irq_base;
	int i;

	ret = 0;
	irq_base = n * 16;
	for (i = 0; i < 16; i++) {
		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		ret |= ((uint64_t)irq->config) << (i * 2);
		vgic_v3_release_irq(irq);
	}

	return (ret);
}

static void
write_config(struct hyp *hyp, int vcpuid, int n, uint64_t val)
{
	struct vgic_v3_irq *irq;
	uint32_t irq_base;
	int i;

	irq_base = n * 16;
	for (i = 0; i < 16; i++) {
		/*
		 * The config can't be changed for SGIs and PPIs. SGIs have
		 * an edge-triggered behaviour, and the register is
		 * implementation defined to be read-only for PPIs.
		 */
		if (irq_base + i < VGIC_PRV_I_NUM)
			continue;

		irq = vgic_v3_get_irq(hyp, vcpuid, irq_base + i);
		if (irq == NULL)
			continue;

		/* Bit 0 is RES0 */
		irq->config = (val >> (i * 2)) & VGIC_CONFIG_MASK;
		vgic_v3_release_irq(irq);
	}
}

static uint64_t
read_route(struct hyp *hyp, int vcpuid, int n)
{
	struct vgic_v3_irq *irq;
	uint64_t mpidr;

	irq = vgic_v3_get_irq(hyp, vcpuid, n);
	if (irq == NULL)
		return (0);

	mpidr = irq->mpidr;
	vgic_v3_release_irq(irq);

	return (mpidr);
}

static void
write_route(struct hyp *hyp, int vcpuid, int n, uint64_t val, u_int offset,
    u_int size)
{
	struct vgic_v3_irq *irq;

	irq = vgic_v3_get_irq(hyp, vcpuid, n);
	if (irq == NULL)
		return;

	/* TODO: Move the interrupt to the correct pending list */
	irq->mpidr = gic_reg_value_64(irq->mpidr, val, offset, size) & GICD_AFF;
	vgic_v3_release_irq(irq);
}

/*
 * Distributor register handlers.
 */
/* GICD_CTLR */
static void
dist_ctlr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	struct vgic_v3_dist *dist;

	dist = &hyp->vgic_dist;
	mtx_lock_spin(&dist->dist_mtx);
	*rval = dist->gicd_ctlr;
	mtx_unlock_spin(&dist->dist_mtx);

	/* Writes are never pending */
	*rval &= ~GICD_CTLR_RWP;
}

static void
dist_ctlr_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	struct vgic_v3_dist *dist;

	MPASS(offset == 0);
	MPASS(size == 4);
	dist = &hyp->vgic_dist;

	/*
	 * GICv2 backwards compatibility is not implemented so
	 * ARE_NS is RAO/WI. This means EnableGrp1 is RES0.
	 *
	 * EnableGrp1A is supported, and RWP is read-only.
	 *
	 * All other bits are RES0 from non-secure mode as we
	 * implement as if we are in a system with two security
	 * states.
	 */
	wval &= GICD_CTLR_G1A;
	wval |= GICD_CTLR_ARE_NS;
	mtx_lock_spin(&dist->dist_mtx);
	dist->gicd_ctlr = wval;
	/* TODO: Wake any vcpus that have interrupts pending */
	mtx_unlock_spin(&dist->dist_mtx);
}

/* GICD_TYPER */
static void
dist_typer_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	uint32_t typer;

	typer = (10 - 1) << GICD_TYPER_IDBITS_SHIFT;
	typer |= GICD_TYPER_MBIS;
	/* ITLinesNumber: */
	typer |= howmany(VGIC_NIRQS + 1, 32) - 1;

	*rval = typer;
}

/* GICD_IIDR */
static void
dist_iidr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	*rval = VGIC_IIDR;
}

/* GICD_SETSPI_NSR & GICD_CLRSPI_NSR */
static void
dist_setclrspi_nsr_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	uint32_t irqid;

	MPASS(offset == 0);
	MPASS(size == 4);
	irqid = wval & GICD_SPI_INTID_MASK;
	vgic_v3_inject_irq(hyp, vcpuid, irqid, reg == GICD_SETSPI_NSR);
}

/* GICD_ISENABLER */
static void
dist_isenabler_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_ISENABLER(0)) / 4;
	/* GICD_ISENABLER0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	*rval = read_enabler(hyp, vcpuid, n);
}

static void
dist_isenabler_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	int n;

	MPASS(offset == 0);
	MPASS(size == 4);
	n = (reg - GICD_ISENABLER(0)) / 4;
	/* GICD_ISENABLER0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	write_enabler(hyp, vcpuid, n, true, wval);
}

/* GICD_ICENABLER */
static void
dist_icenabler_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_ICENABLER(0)) / 4;
	/* GICD_ICENABLER0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	*rval = read_enabler(hyp, vcpuid, n);
}

static void
dist_icenabler_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	int n;

	MPASS(offset == 0);
	MPASS(size == 4);
	n = (reg - GICD_ISENABLER(0)) / 4;
	/* GICD_ICENABLER0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	write_enabler(hyp, vcpuid, n, false, wval);
}

/* GICD_ISPENDR */
static void
dist_ispendr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_ISPENDR(0)) / 4;
	/* GICD_ISPENDR0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	*rval = read_pendr(hyp, vcpuid, n);
}

static void
dist_ispendr_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	int n;

	MPASS(offset == 0);
	MPASS(size == 4);
	n = (reg - GICD_ISPENDR(0)) / 4;
	/* GICD_ISPENDR0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	write_pendr(hyp, vcpuid, n, true, wval);
}

/* GICD_ICPENDR */
static void
dist_icpendr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_ICPENDR(0)) / 4;
	/* GICD_ICPENDR0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	*rval = read_pendr(hyp, vcpuid, n);
}

static void
dist_icpendr_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	int n;

	MPASS(offset == 0);
	MPASS(size == 4);
	n = (reg - GICD_ICPENDR(0)) / 4;
	/* GICD_ICPENDR0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	write_pendr(hyp, vcpuid, n, false, wval);
}

/* GICD_ISACTIVER */
/* Affinity routing is enabled so isactiver0 is RAZ/WI */
static void
dist_isactiver_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_ISACTIVER(0)) / 4;
	/* GICD_ISACTIVER0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	*rval = read_activer(hyp, vcpuid, n);
}

static void
dist_isactiver_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	int n;

	MPASS(offset == 0);
	MPASS(size == 4);
	n = (reg - GICD_ISACTIVER(0)) / 4;
	/* GICD_ISACTIVE0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	write_activer(hyp, vcpuid, n, true, wval);
}

/* GICD_ICACTIVER */
static void
dist_icactiver_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_ICACTIVER(0)) / 4;
	/* GICD_ICACTIVE0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	*rval = read_activer(hyp, vcpuid, n);
}

static void
dist_icactiver_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	int n;

	MPASS(offset == 0);
	MPASS(size == 4);
	n = (reg - GICD_ICACTIVER(0)) / 4;
	/* GICD_ICACTIVE0 is RAZ/WI so handled separately */
	MPASS(n > 0);
	write_activer(hyp, vcpuid, n, false, wval);
}

/* GICD_IPRIORITYR */
/* Affinity routing is enabled so ipriorityr0-7 is RAZ/WI */
static void
dist_ipriorityr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_IPRIORITYR(0)) / 4;
	/* GICD_IPRIORITY0-7 is RAZ/WI so handled separately */
	MPASS(n > 7);
	*rval = read_priorityr(hyp, vcpuid, n);
}

static void
dist_ipriorityr_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	u_int irq_base;

	irq_base = (reg - GICD_IPRIORITYR(0)) + offset;
	/* GICD_IPRIORITY0-7 is RAZ/WI so handled separately */
	MPASS(irq_base > 31);
	write_priorityr(hyp, vcpuid, irq_base, size, wval);
}

/* GICD_ICFGR */
static void
dist_icfgr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_ICFGR(0)) / 4;
	/* GICD_ICFGR0-1 are RAZ/WI so handled separately */
	MPASS(n > 1);
	*rval = read_config(hyp, vcpuid, n);
}

static void
dist_icfgr_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	int n;

	MPASS(offset == 0);
	MPASS(size == 4);
	n = (reg - GICD_ICFGR(0)) / 4;
	/* GICD_ICFGR0-1 are RAZ/WI so handled separately */
	MPASS(n > 1);
	write_config(hyp, vcpuid, n, wval);
}

/* GICD_IROUTER */
static void
dist_irouter_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICD_IROUTER(0)) / 8;
	/* GICD_IROUTER0-31 don't exist */
	MPASS(n > 31);
	*rval = read_route(hyp, vcpuid, n);
}

static void
dist_irouter_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	int n;

	n = (reg - GICD_IROUTER(0)) / 8;
	/* GICD_IROUTER0-31 don't exist */
	MPASS(n > 31);
	write_route(hyp, vcpuid, n, wval, offset, size);
}

static bool
vgic_register_read(struct hyp *hyp, struct vgic_register *reg_list,
    u_int reg_list_size, int vcpuid, u_int reg, u_int size,
    uint64_t *rval, void *arg)
{
	u_int i, offset;

	for (i = 0; i < reg_list_size; i++) {
		if (reg_list[i].start <= reg && reg_list[i].end >= reg + size) {
			offset = reg & reg_list[i].size - 1;
			reg -= offset;
			if ((reg_list[i].flags & size) != 0) {
				reg_list[i].read(hyp, vcpuid, reg, rval, NULL);

				/* Move the bits into the correct place */
				*rval >>= (offset * 8);
				if (size < 8) {
					*rval &= (1ul << (size * 8)) - 1;
				}
			} else {
				panic("TODO: Handle invalid register size: "
				    "reg %x size %d", reg, size);
			}
			return (true);
		}
	}
	return (false);
}

static bool
vgic_register_write(struct hyp *hyp, struct vgic_register *reg_list,
    u_int reg_list_size, int vcpuid, u_int reg, u_int size,
    uint64_t wval, void *arg)
{
	u_int i, offset;

	for (i = 0; i < reg_list_size; i++) {
		if (reg_list[i].start <= reg && reg_list[i].end >= reg + size) {
			offset = reg & reg_list[i].size - 1;
			reg -= offset;
			if ((reg_list[i].flags & size) != 0) {
				reg_list[i].write(hyp, vcpuid, reg, offset,
				    size, wval, NULL);
			} else {
				panic("TODO: Handle invalid register size: "
				    "reg %x size %d", reg, size);
			}
			return (true);
		}
	}
	return (false);
}

static int
dist_read(void *vm, int vcpuid, uint64_t fault_ipa, uint64_t *rval,
    int size, void *arg)
{
	struct hyp *hyp = vm_get_cookie(vm);
	struct vgic_v3_dist *dist = &hyp->vgic_dist;
	uint64_t reg;

	/* Check the register is one of ours and is the correct size */
	if (fault_ipa < dist->start || fault_ipa + size > dist->end) {
		return (EINVAL);
	}

	reg = fault_ipa - dist->start;
	/* Check the register is correctly aligned */
	if ((reg & (size - 1)) != 0)
		return (EINVAL);

	if (vgic_register_read(hyp, dist_registers, nitems(dist_registers),
	    vcpuid, reg, size, rval, NULL))
		return (0);

	/* TODO: Check the correct behaviour */
	printf("%s: %lx\n", __func__, fault_ipa - dist->start);
	*rval = 0;

	return (0);
}

static int
dist_write(void *vm, int vcpuid, uint64_t fault_ipa, uint64_t wval,
    int size, void *arg)
{
	struct hyp *hyp = vm_get_cookie(vm);
	struct vgic_v3_dist *dist = &hyp->vgic_dist;
	uint64_t reg;

	/* Check the register is one of ours and is the correct size */
	if (fault_ipa < dist->start || fault_ipa + size > dist->end) {
		return (EINVAL);
	}

	reg = fault_ipa - dist->start;
	/* Check the register is correctly aligned */
	if ((reg & (size - 1)) != 0)
		return (EINVAL);

	if (vgic_register_write(hyp, dist_registers, nitems(dist_registers),
	    vcpuid, reg, size, wval, NULL))
		return (0);

	panic("%s: %lx\n", __func__, fault_ipa - dist->start);
	return (0);
}

/*
 * Redistributor register handlers.
 *
 * RD_base:
 */
/* GICR_CTLR */
static void
redist_ctlr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	/* LPIs not supported */
	*rval = 0;
}

/* GICR_IIDR */
static void
redist_iidr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	*rval = VGIC_IIDR;
}

/* GICR_TYPER */
static void
redist_typer_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	struct vgic_v3_redist *redist;

	redist = &hyp->ctx[vcpuid].vgic_redist;
	*rval = redist->gicr_typer;
}

/* GICR_PROPBASER */
static void
redist_propbaser_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	struct vgic_v3_redist *redist;

	redist = &hyp->ctx[vcpuid].vgic_redist;
	*rval = atomic_load_64(&redist->gicr_propbaser);
}

static void
redist_propbaser_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	struct vgic_v3_redist *redist;

	redist = &hyp->ctx[vcpuid].vgic_redist;
	/* Update the new value to include any non-overridden data */
	wval = gic_reg_value_64(redist->gicr_propbaser, wval, offset, size);
	wval &= ~(GICR_PROPBASER_OUTER_CACHE_MASK |
	    GICR_PROPBASER_SHARE_MASK | GICR_PROPBASER_CACHE_MASK);
	wval |=
	    (GICR_PROPBASER_SHARE_OS << GICR_PROPBASER_SHARE_SHIFT) |
	    (GICR_PROPBASER_CACHE_NIWAWB << GICR_PROPBASER_CACHE_SHIFT);
	atomic_store_64(&redist->gicr_propbaser, wval);
}

/* GICR_PENDBASER */
static void
redist_pendbaser_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	struct vgic_v3_redist *redist;

	redist = &hyp->ctx[vcpuid].vgic_redist;
	*rval = redist->gicr_pendbaser;
}

static void
redist_pendbaser_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	struct vgic_v3_redist *redist;

	redist = &hyp->ctx[vcpuid].vgic_redist;
	/* Update the new value to include any non-overridden data */
	wval = gic_reg_value_64(redist->gicr_pendbaser, wval, offset, size);
	wval &= ~(GICR_PENDBASER_OUTER_CACHE_MASK |
	    GICR_PENDBASER_SHARE_MASK | GICR_PENDBASER_CACHE_MASK);
	wval |=
	    (GICR_PENDBASER_SHARE_OS << GICR_PENDBASER_SHARE_SHIFT) |
	    (GICR_PENDBASER_CACHE_NIWAWB << GICR_PENDBASER_CACHE_SHIFT);
	redist->gicr_pendbaser = wval;
}

/*
 * SGI_base:
 */
/* GICR_ISENABLER0 */
static void
redist_ienabler0_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	*rval = read_enabler(hyp, vcpuid, 0);
}

static void
redist_isenabler0_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	MPASS(offset == 0);
	MPASS(size == 4);
	write_enabler(hyp, vcpuid, 0, true, wval);
}

/* GICR_ICENABLER0 */
static void
redist_icenabler0_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	MPASS(offset == 0);
	MPASS(size == 4);
	write_enabler(hyp, vcpuid, 0, false, wval);
}

/* GICR_ISPENDR0 */
static void
redist_ipendr0_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	*rval = read_pendr(hyp, vcpuid, 0);
}

static void
redist_ispendr0_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	MPASS(offset == 0);
	MPASS(size == 4);
	write_pendr(hyp, vcpuid, 0, true, wval);
}

/* GICR_ICPENDR0 */
static void
redist_icpendr0_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	MPASS(offset == 0);
	MPASS(size == 4);
	write_pendr(hyp, vcpuid, 0, false, wval);
}

/* GICR_ISACTIVER0 */
static void
redist_iactiver0_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	*rval = read_activer(hyp, vcpuid, 0);
}

static void
redist_isactiver0_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	write_activer(hyp, vcpuid, 0, true, wval);
}

/* GICR_ICACTIVER0 */
static void
redist_icactiver0_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	write_activer(hyp, vcpuid, 0, false, wval);
}

/* GICR_IPRIORITYR */
static void
redist_ipriorityr_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	int n;

	n = (reg - GICR_IPRIORITYR(0)) / 4;
	*rval = read_priorityr(hyp, vcpuid, n);
}

static void
redist_ipriorityr_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	u_int irq_base;

	irq_base = (reg - GICR_IPRIORITYR(0)) + offset;
	write_priorityr(hyp, vcpuid, irq_base, size, wval);
}

/* GICR_ICFGR1 */
static void
redist_icfgr1_read(struct hyp *hyp, int vcpuid, u_int reg, uint64_t *rval,
    void *arg)
{
	*rval = read_config(hyp, vcpuid, 0);
}

static void
redist_icfgr1_write(struct hyp *hyp, int vcpuid, u_int reg, u_int offset,
    u_int size, uint64_t wval, void *arg)
{
	MPASS(offset == 0);
	MPASS(size == 4);
	write_config(hyp, vcpuid, 0, wval);
}

static int
redist_read(void *vm, int vcpuid, uint64_t fault_ipa, uint64_t *rval,
    int size, void *arg)
{
	struct hyp *hyp = vm_get_cookie(vm);
	struct vgic_v3_redist *redist = &hyp->ctx[vcpuid].vgic_redist;
	uint64_t reg;

	/* Check the register is one of ours and is the correct size */
	if (fault_ipa < redist->start || fault_ipa + size > redist->end) {
		return (EINVAL);
	}

	reg = fault_ipa - redist->start;
	/* Check the register is correctly aligned */
	if ((reg & (size - 1)) != 0)
		return (EINVAL);

	if (reg < GICR_RD_BASE_SIZE) {
		if (vgic_register_read(hyp, redist_rd_registers,
		    nitems(redist_rd_registers), vcpuid, reg, size, rval, NULL))
			return (0);
	} else if (reg < (GICR_SGI_BASE + GICR_SGI_BASE_SIZE)) {
		if (vgic_register_read(hyp, redist_sgi_registers,
		    nitems(redist_sgi_registers), vcpuid,
		    reg - GICR_SGI_BASE, size, rval, NULL))
			return (0);
	}

	panic("%s: %lx", __func__, reg);
}

static int
redist_write(void *vm, int vcpuid, uint64_t fault_ipa, uint64_t wval,
    int size, void *arg)
{
	struct hyp *hyp = vm_get_cookie(vm);
	struct vgic_v3_redist *redist = &hyp->ctx[vcpuid].vgic_redist;
	uint64_t reg;

	/* Check the register is one of ours and is the correct size */
	if (fault_ipa < redist->start || fault_ipa + size > redist->end) {
		return (EINVAL);
	}

	reg = fault_ipa - redist->start;
	/* Check the register is correctly aligned */
	if ((reg & (size - 1)) != 0)
		return (EINVAL);

	if (reg < GICR_RD_BASE_SIZE) {
		if (vgic_register_write(hyp, redist_rd_registers,
		    nitems(redist_rd_registers), vcpuid, reg, size, wval, NULL))
			return (0);
	} else if (reg < (GICR_SGI_BASE + GICR_SGI_BASE_SIZE)) {
		if (vgic_register_write(hyp, redist_sgi_registers,
		    nitems(redist_sgi_registers), vcpuid,
		    reg - GICR_SGI_BASE, size, wval, NULL))
			return (0);
	}

	panic("%s: %lx", __func__, reg);
}

int
vgic_v3_icc_sgi1r_read(void *vm, int vcpuid, vmm_register_t *rval, void *arg)
{
	/*
	 * TODO: Inject an unknown exception.
	 */
	*rval = 0;
	return (0);
}

/* vgic_v3_icc_sgi1r_write currently only handles 16 CPUs */
CTASSERT(VM_MAXCPU <= 16);
int
vgic_v3_icc_sgi1r_write(void *vm, int vcpuid, vmm_register_t rval, void *arg)
{
	struct hyp *hyp;
	cpuset_t active_cpus;
	uint32_t irqid;
	int cpus, vcpu;

	hyp = vm_get_cookie(vm);
	active_cpus = vm_active_cpus(vm);
	irqid = (rval >> ICC_SGI1R_EL1_SGIID_SHIFT) & ICC_SGI1R_EL1_SGIID_MASK;
	if ((rval & ICC_SGI1R_EL1_IRM) == 0) {
		/*
		 * TODO: Support on mure than 16 CPUs. This is the mask for the
		 * affinity bits. These should be 0.
		 */
		if ((rval & 0xff00ff00ff000ul) != 0)
			return (0);
		cpus = rval & 0xff;
		vcpu = 0;
		while (cpus > 0) {
			if (CPU_ISSET(vcpu, &active_cpus) && vcpu != vcpuid) {
				vgic_v3_inject_irq(hyp, vcpu, irqid, true);
			}
			vcpu++;
			cpus >>= 1;
		}
	} else {
		/* Send an IPI to all CPUs other than the current CPU */
		for (vcpu = 0; vcpu < VM_MAXCPU; vcpu++) {
			if (CPU_ISSET(vcpu, &active_cpus) && vcpu != vcpuid) {
				vgic_v3_inject_irq(hyp, vcpu, irqid, true);
			}
		}
	}

	return (0);
}

static void
vgic_v3_mmio_init(struct hyp *hyp)
{
	struct vgic_v3_dist *dist;
	struct vgic_v3_irq *irq;
	int i;

	/* Allocate memory for the SPIs */
	dist = &hyp->vgic_dist;
	dist->irqs = malloc((VGIC_NIRQS - VGIC_PRV_I_NUM) *
	    sizeof(*dist->irqs), M_VGIC_V3, M_WAITOK | M_ZERO);

	for (i = 0; i < VGIC_NIRQS - VGIC_PRV_I_NUM; i++) {
		irq = &dist->irqs[i];

		mtx_init(&irq->irq_spinmtx, "VGIC IRQ spinlock", NULL,
		    MTX_SPIN);

		irq->irq = i + VGIC_PRV_I_NUM;
	}
}

static void
vgic_v3_mmio_destroy(struct hyp *hyp)
{
	struct vgic_v3_dist *dist = &hyp->vgic_dist;
	struct vgic_v3_irq *irq;
	int i;

	for (i = 0; i < VGIC_NIRQS - VGIC_PRV_I_NUM; i++) {
		irq = &dist->irqs[i];

		mtx_destroy(&irq->irq_spinmtx);
	}

	free(dist->irqs, M_VGIC_V3);
}

int
vgic_v3_attach_to_vm(struct vm *vm, uint64_t dist_start, size_t dist_size,
    uint64_t redist_start, size_t redist_size)
{
	struct hyp *hyp = vm_get_cookie(vm);
	struct vgic_v3_dist *dist = &hyp->vgic_dist;
	struct vgic_v3_redist *redist;
	int i;

	/* Set the distributor address and size for trapping guest access. */
	dist->start = dist_start;
	dist->end = dist_start + dist_size;

	for (i = 0; i < VM_MAXCPU; i++) {
		redist = &hyp->ctx[i].vgic_redist;
		/* Set the redistributor address and size. */
		redist->start = redist_start;
		redist->end = redist_start + redist_size;
	}

	vm_register_inst_handler(vm, dist_start, dist_size, dist_read,
	    dist_write);
	vm_register_inst_handler(vm, redist_start, redist_size, redist_read,
	    redist_write);

	vgic_v3_mmio_init(hyp);

	hyp->vgic_attached = true;

	return (0);
}

void
vgic_v3_detach_from_vm(struct vm *vm)
{
	struct hyp *hyp = vm_get_cookie(vm);

	if (hyp->vgic_attached) {
		hyp->vgic_attached = false;
		vgic_v3_mmio_destroy(hyp);
	}
}

static struct vgic_v3_irq *
vgic_v3_get_irq(struct hyp *hyp, int vcpuid, uint32_t irqid)
{
	struct vgic_v3_cpu_if *cpu_if;
	struct vgic_v3_dist *dist;
	struct vgic_v3_irq *irq;

	if (irqid < VGIC_PRV_I_NUM) {
		if (vcpuid < 0 || vcpuid >= nitems(hyp->ctx))
			return (NULL);

		cpu_if = &hyp->ctx[vcpuid].vgic_cpu_if;
		irq = &cpu_if->private_irqs[irqid];
	} else if (irqid <= GIC_LAST_SPI) {
		dist = &hyp->vgic_dist;
		irqid -= VGIC_PRV_I_NUM;
		if (irqid >= VGIC_NIRQS)
			return (NULL);
		irq = &dist->irqs[irqid];
	} else if (irqid < GIC_FIRST_LPI) {
		return (NULL);
	} else {
		panic("TODO: %s: Support LPIs (irq = %x)", __func__, irqid);
	}

	mtx_lock_spin(&irq->irq_spinmtx);
	return (irq);
}

static void
vgic_v3_release_irq(struct vgic_v3_irq *irq)
{

	mtx_unlock_spin(&irq->irq_spinmtx);
}

bool
vgic_v3_vcpu_pending_irq(struct hypctx *hypctx)
{
	struct vgic_v3_cpu_if *cpu_if;
	bool empty;

	cpu_if = &hypctx->vgic_cpu_if;
	mtx_lock_spin(&cpu_if->lr_mtx);
	empty = TAILQ_EMPTY(&cpu_if->irq_act_pend);
	mtx_unlock_spin(&cpu_if->lr_mtx);

	return (!empty);
}

static bool
vgic_v3_check_irq(struct vgic_v3_irq *irq, bool level)
{
	/*
	 * Only inject if:
	 *  - Level-triggered IRQ: level changes low -> high
	 *  - Edge-triggered IRQ: level is high
	 */
	switch (irq->config & VGIC_CONFIG_MASK) {
	case VGIC_CONFIG_LEVEL:
		return (level != irq->level);
	case VGIC_CONFIG_EDGE:
		return (level);
	default:
		break;
	}

	return (false);
}

int
vgic_v3_inject_irq(struct hyp *hyp, int vcpuid, uint32_t irqid, bool level)
{

	struct vgic_v3_cpu_if *cpu_if;
	struct vgic_v3_irq *irq;
	uint64_t irouter;
	bool notify;

	KASSERT(vcpuid == -1 || irqid < VGIC_PRV_I_NUM,
	    ("%s: SPI/LPI with vcpuid set: irq %u vcpuid %u", __func__, irqid,
	    vcpuid));

	irq = vgic_v3_get_irq(hyp, vcpuid, irqid);
	if (irq == NULL) {
		eprintf("Malformed IRQ %u.\n", irqid);
		return (1);
	}

	irouter = irq->mpidr;
	KASSERT(vcpuid == -1 || vcpuid == irouter,
	    ("%s: Interrupt %u has bad cpu affinity: vcpuid %u affinity %#lx",
	    __func__, irqid, vcpuid, irouter));
	KASSERT(irouter < VM_MAXCPU,
	    ("%s: Interrupt %u sent to invalid vcpu %lu", __func__, irqid,
	    irouter));

	if (vcpuid == -1)
		vcpuid = irouter;
	if (vcpuid >= VM_MAXCPU) {
		vgic_v3_release_irq(irq);
		return (1);
	}

	notify = false;
	cpu_if = &hyp->ctx[vcpuid].vgic_cpu_if;

	mtx_lock_spin(&cpu_if->lr_mtx);

	if (!vgic_v3_check_irq(irq, level)) {
		goto out;
	}

	if ((irq->config & VGIC_CONFIG_MASK) == VGIC_CONFIG_LEVEL)
		irq->level = level;
	else /* VGIC_CONFIG_EDGE */
		irq->pending = true;

	notify = vgic_v3_queue_irq(hyp, cpu_if, vcpuid, irq);

out:
	mtx_unlock_spin(&cpu_if->lr_mtx);
	vgic_v3_release_irq(irq);

	if (notify)
		vcpu_notify_event(hyp->vm, vcpuid, false);

	return (0);
}

int
vgic_v3_inject_msi(struct hyp *hyp, uint64_t msg, uint64_t addr)
{
	struct vgic_v3_dist *dist = &hyp->vgic_dist;
	uint64_t reg;

	/* This is a 4 byte register */
	if (addr < dist->start || addr + 4 > dist->end) {
		return (EINVAL);
	}

	reg = addr - dist->start;
	if (reg != GICD_SETSPI_NSR)
		return (EINVAL);

	return (vgic_v3_inject_irq(hyp, -1, msg, true));
}

void
vgic_v3_flush_hwstate(void *arg)
{
	struct hypctx *hypctx;
	struct vgic_v3_cpu_if *cpu_if;
	struct vgic_v3_irq *irq;
	int i;

	hypctx = arg;
	cpu_if = &hypctx->vgic_cpu_if;

	/*
	 * All Distributor writes have been executed at this point, do not
	 * protect Distributor reads with a mutex.
	 *
	 * This is callled with all interrupts disabled, so there is no need for
	 * a List Register spinlock either.
	 */
	mtx_lock_spin(&cpu_if->lr_mtx);

	cpu_if->ich_hcr_el2 &= ~ICH_HCR_EL2_UIE;

	/* Exit early if there are no buffered interrupts */
	if (TAILQ_EMPTY(&cpu_if->irq_act_pend))
		goto out;

	KASSERT(cpu_if->ich_lr_used == 0, ("%s: Used LR count not zero %u",
	    __func__, cpu_if->ich_lr_used));

	i = 0;
	cpu_if->ich_elrsr_el2 = (1 << cpu_if->ich_lr_num) - 1;
	TAILQ_FOREACH(irq, &cpu_if->irq_act_pend, act_pend_list) {
		/* No free list register, stop searching for IRQs */
		if (i == cpu_if->ich_lr_num)
			break;

		if (!irq->enabled)
			continue;

		cpu_if->ich_lr_el2[i] = ICH_LR_EL2_GROUP1 |
		    ((uint64_t)irq->priority << ICH_LR_EL2_PRIO_SHIFT) |
		    irq->irq;

		if (irq->active) {
			cpu_if->ich_lr_el2[i] |= ICH_LR_EL2_STATE_ACTIVE;
		}

#ifdef notyet
		/* TODO: Check why this is needed */
		if ((irq->config & _MASK) == LEVEL)
			cpu_if->ich_lr_el2[i] |= ICH_LR_EL2_EOI;
#endif

		if (!irq->active && vgic_v3_irq_pending(irq)) {
			cpu_if->ich_lr_el2[i] |= ICH_LR_EL2_STATE_PENDING;

			/*
			 * This IRQ is now pending on the guest. Allow for
			 * another edge that could cause the interrupt to
			 * be raised again.
			 */
			if ((irq->config & VGIC_CONFIG_MASK) ==
			    VGIC_CONFIG_EDGE) {
				irq->pending = false;
			}
		}

		i++;
	}
	cpu_if->ich_lr_used = i;

out:
	mtx_unlock_spin(&cpu_if->lr_mtx);
}

void
vgic_v3_sync_hwstate(void *arg)
{
	struct hypctx *hypctx;
	struct vgic_v3_cpu_if *cpu_if;
	struct vgic_v3_irq *irq;
	uint64_t lr;
	int i;

	hypctx = arg;
	cpu_if = &hypctx->vgic_cpu_if;

	/* Exit early if there are no buffered interrupts */
	if (cpu_if->ich_lr_used == 0)
		return;

	/*
	 * Check on the IRQ state after running the guest. ich_lr_used and
	 * ich_lr_el2 are only ever used within this thread so is safe to
	 * access unlocked.
	 */
	for (i = 0; i < cpu_if->ich_lr_used; i++) {
		lr = cpu_if->ich_lr_el2[i];
		cpu_if->ich_lr_el2[i] = 0;

		irq = vgic_v3_get_irq(hypctx->hyp, hypctx->vcpu,
		    ICH_LR_EL2_VINTID(lr));
		if (irq == NULL)
			continue;

		irq->active = (lr & ICH_LR_EL2_STATE_ACTIVE) != 0;

		if ((irq->config & VGIC_CONFIG_MASK) == VGIC_CONFIG_EDGE) {
			/*
			 * If we have an edge triggered IRQ preserve the
			 * pending bit until the IRQ has been handled.
			 */
			if ((lr & ICH_LR_EL2_STATE_PENDING) != 0) {
				irq->pending = true;
			}
		} else {
			/*
			 * If we have a level triggerend IRQ remove the
			 * pending bit if the IRQ has been handled.
			 * The level is separate, so may still be high
			 * triggering another IRQ.
			 */
			if ((lr & ICH_LR_EL2_STATE_PENDING) == 0) {
				irq->pending = false;
			}
		}

		/* Lock to update irq_act_pend */
		mtx_lock_spin(&cpu_if->lr_mtx);
		if (irq->active) {
			/* Ensure the active IRQ is at the head of the list */
			TAILQ_REMOVE(&cpu_if->irq_act_pend, irq, act_pend_list);
			TAILQ_INSERT_HEAD(&cpu_if->irq_act_pend, irq,
			    act_pend_list);
		} else if (!vgic_v3_irq_pending(irq)) {
			/* If pending or active remove from the list */
			TAILQ_REMOVE(&cpu_if->irq_act_pend, irq, act_pend_list);
			irq->on_aplist = false;
		}
		mtx_unlock_spin(&cpu_if->lr_mtx);
		vgic_v3_release_irq(irq);
	}

	cpu_if->ich_hcr_el2 &= ~ICH_HCR_EL2_EOICOUNT_MASK;
	cpu_if->ich_lr_used = 0;
}

static int
vgic_probe(device_t dev)
{
	if (!gic_get_vgic(dev))
		return (EINVAL);

	/* We currently only support the GICv3 */
	if (gic_get_hw_rev(dev) < 3)
		return (EINVAL);

	device_set_desc(dev, "Virtual GIC");
	return (BUS_PROBE_DEFAULT);
}

static int
vgic_attach(device_t dev)
{
	have_vgic = true;
	return (0);
}

static device_method_t vgic_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		vgic_probe),
	DEVMETHOD(device_attach,	vgic_attach),

	/* End */
	DEVMETHOD_END
};

DEFINE_CLASS_0(vgic, vgic_driver, vgic_methods, 0);

DRIVER_MODULE(vgic, gic, vgic_driver, 0, 0);

bool
vgic_present(void)
{
	return (have_vgic);
}

void
vgic_v3_init(uint64_t ich_vtr_el2)
{
	uint32_t pribits, prebits;

	MPASS(have_vgic);

	pribits = ICH_VTR_EL2_PRIBITS(ich_vtr_el2);
	switch (pribits) {
	case 5:
		virt_features.min_prio = 0xf8;
	case 6:
		virt_features.min_prio = 0xfc;
	case 7:
		virt_features.min_prio = 0xfe;
	case 8:
		virt_features.min_prio = 0xff;
	}

	prebits = ICH_VTR_EL2_PREBITS(ich_vtr_el2);
	switch (prebits) {
	case 5:
		virt_features.ich_apr_num = 1;
	case 6:
		virt_features.ich_apr_num = 2;
	case 7:
		virt_features.ich_apr_num = 4;
	}

	virt_features.ich_lr_num = ICH_VTR_EL2_LISTREGS(ich_vtr_el2);
}
