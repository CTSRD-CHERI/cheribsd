/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Alfredo Mazzinghi <am2419@cl.cam.ac.uk>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include "opt_hwpmc_hooks.h"

#include <sys/param.h>
#include <sys/pmckern.h>

#include <machine/stack.h>
#include <machine/riscvreg.h>

#include <dev/hwpmc/hwpmc_riscv.h>

#define	RISCV_NCOUNTERS	31
#define	TOOOBA_PMC_CAPS		(PMC_CAP_SYSTEM | PMC_CAP_READ | PMC_CAP_WRITE)

/*
 * HW pmc register operations
 */
struct riscv_csr_desc {
	/*
	 * XXX the fixed event mapping should go away once we are able to
	 * reconfigure counters via mcalls.
	 */
	enum pmc_event hpm_ev;		/* Fixed event mapping from firmware */
	uint64_t (*hpm_read)(void);	/* Read function for csr access */
	void (*hpm_event)(uint64_t);	/* Configure event for the HWPMC CSR */
};

/*
 * Per-processor information.
 */
struct riscv_pcpu {
	struct pmc_hw	*pc_riscvpmcs;
	uint64_t	pc_start_values[RISCV_NCOUNTERS];
	uint64_t	pc_stop_values[RISCV_NCOUNTERS];
	uint64_t	pc_saved_values[RISCV_NCOUNTERS];
};

int riscv_npmcs;
static struct riscv_pcpu **riscv_pcpu;

#define	RISCV_HPM_READ(hpmn)					\
static inline uint64_t riscv_hpm##hpmn##_rd(void) {		\
	return csr_read64(mhpmcounter##hpmn);			\
}

#define	RISCV_HPM_EVENT(hpmn)					\
static inline void riscv_hpm##hpmn##_event(uint64_t ev) {	\
	/* SBI_CALL(__SBI_EXT_CHERI, SBI_CHERI_SET_HWPMC, hpmn, ev); */	\
}

#define	RISCV_HPM_FN(hpmn)	\
	RISCV_HPM_READ(hpmn)	\
	RISCV_HPM_EVENT(hpmn)

RISCV_HPM_FN(3)
RISCV_HPM_FN(4)
RISCV_HPM_FN(5)
RISCV_HPM_FN(6)
RISCV_HPM_FN(7)
RISCV_HPM_FN(8)
RISCV_HPM_FN(9)
RISCV_HPM_FN(10)
RISCV_HPM_FN(11)
RISCV_HPM_FN(12)
RISCV_HPM_FN(13)
RISCV_HPM_FN(14)
RISCV_HPM_FN(15)
RISCV_HPM_FN(16)
RISCV_HPM_FN(17)
RISCV_HPM_FN(18)
RISCV_HPM_FN(19)
RISCV_HPM_FN(20)
RISCV_HPM_FN(21)
RISCV_HPM_FN(22)
RISCV_HPM_FN(23)
RISCV_HPM_FN(24)
RISCV_HPM_FN(25)
RISCV_HPM_FN(26)
RISCV_HPM_FN(27)
RISCV_HPM_FN(28)
RISCV_HPM_FN(29)
RISCV_HPM_FN(30)
RISCV_HPM_FN(31)

static inline uint64_t
riscv_hpm_cycle_rd(void)
{
	return (csr_read64(cycle));
}

static inline uint64_t
riscv_hpm_instr_rd(void)
{
	return (csr_read64(instret));
}

static inline uint64_t
riscv_hpm_time_rd(void)
{
	return (csr_read64(time));
}

/*
 * Fixed hwpmc register mappings
 * XXX-AM: These should go away once we have a way to program counters
 * via an SBI extension.
 */
static struct riscv_csr_desc *csr_map;
static struct riscv_csr_desc toooba_csr_map[RISCV_NCOUNTERS] = {
	{PMC_EV_RISCV_CYCLES,		riscv_hpm_cycle_rd,	NULL},
	{PMC_EV_RISCV_INSTRET,		riscv_hpm_instr_rd,	NULL},
	{PMC_EV_RISCV_TIME,		riscv_hpm_time_rd,	NULL},
	{PMC_EV_RISCV_EVENT_01H,	riscv_hpm3_rd,	riscv_hpm3_event},
	{PMC_EV_RISCV_EVENT_03H,	riscv_hpm4_rd,	riscv_hpm4_event},
	{PMC_EV_RISCV_EVENT_04H,	riscv_hpm5_rd,	riscv_hpm5_event},
	{PMC_EV_RISCV_EVENT_05H,	riscv_hpm6_rd,	riscv_hpm6_event},
	{PMC_EV_RISCV_EVENT_02H,	riscv_hpm7_rd,	riscv_hpm7_event},
	{PMC_EV_RISCV_EVENT_10H,	riscv_hpm8_rd,	riscv_hpm8_event},
	{PMC_EV_RISCV_EVENT_1AH,	riscv_hpm9_rd,	riscv_hpm9_event},
	{PMC_EV_RISCV_EVENT_1BH,	riscv_hpm10_rd,	riscv_hpm10_event},
	{PMC_EV_RISCV_EVENT_2AH,	riscv_hpm11_rd,	riscv_hpm11_event},
	{PMC_EV_RISCV_EVENT_20H,	riscv_hpm12_rd,	riscv_hpm12_event},
	{PMC_EV_RISCV_EVENT_21H,	riscv_hpm13_rd,	riscv_hpm13_event},
	{PMC_EV_RISCV_EVENT_22H,	riscv_hpm14_rd,	riscv_hpm14_event},
	{PMC_EV_RISCV_EVENT_39H,	riscv_hpm15_rd,	riscv_hpm15_event},
	{PMC_EV_RISCV_EVENT_3AH,	riscv_hpm16_rd,	riscv_hpm16_event},
	{PMC_EV_RISCV_EVENT_3BH,	riscv_hpm17_rd,	riscv_hpm17_event},
	{PMC_EV_RISCV_EVENT_30H,	riscv_hpm18_rd,	riscv_hpm18_event},
	{PMC_EV_RISCV_EVENT_31H,	riscv_hpm19_rd,	riscv_hpm19_event},
	{PMC_EV_RISCV_EVENT_32H,	riscv_hpm20_rd,	riscv_hpm20_event},
	{PMC_EV_RISCV_EVENT_33H,	riscv_hpm21_rd,	riscv_hpm21_event},
	{PMC_EV_RISCV_EVENT_34H,	riscv_hpm22_rd,	riscv_hpm22_event},
	{PMC_EV_RISCV_EVENT_61H,	riscv_hpm23_rd,	riscv_hpm23_event},
	{PMC_EV_RISCV_EVENT_62H,	riscv_hpm24_rd,	riscv_hpm24_event},
	{PMC_EV_RISCV_EVENT_42H,	riscv_hpm25_rd,	riscv_hpm25_event},
	{PMC_EV_RISCV_EVENT_43H,	riscv_hpm26_rd,	riscv_hpm26_event},
	{PMC_EV_RISCV_EVENT_64H,	riscv_hpm27_rd,	riscv_hpm27_event},
	{PMC_EV_RISCV_EVENT_41H,	riscv_hpm28_rd,	riscv_hpm28_event},
	{PMC_EV_RISCV_EVENT_44H,	riscv_hpm29_rd,	riscv_hpm29_event},
};

static int
riscv_allocate_pmc(int cpu, int ri, struct pmc *pm,
		    const struct pmc_op_pmcallocate *a)
{
	uint32_t config;
	int i;
	enum pmc_event pe;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
		("[riscv,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < riscv_npmcs,
		("[riscv,%d] illegal PMC index %d", __LINE__, ri));

	if (a->pm_class != PMC_CLASS_RISCV)
		return (EINVAL);
	pe = a->pm_ev;

	for (i = 0; i < RISCV_NCOUNTERS; i++) {
		if (csr_map[i].hpm_ev == pe) {
			config = i;
			break;
		}
	}
	if (i == RISCV_NCOUNTERS)
		return (EINVAL);

	pm->pm_md.pm_riscv.pm_riscv_evsel = config;

	PMCDBG2(MDP, ALL, 2, "riscv-allocate ri=%d -> config=0x%x", ri, config);

	return (0);
}

static int
riscv_config_pmc(int cpu, int ri, struct pmc *pm)
{
	struct pmc_hw *phw;

	PMCDBG3(MDP, CFG, 1, "cpu=%d ri=%d pm=%p", cpu, ri, pm);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
		("[riscv,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < riscv_npmcs,
		("[riscv,%d] illegal row-index %d", __LINE__, ri));

	phw = &riscv_pcpu[cpu]->pc_riscvpmcs[ri];

	KASSERT(pm == NULL || phw->phw_pmc == NULL,
		("[riscv,%d] pm=%p phw->pm=%p hwpmc not unconfigured",
		 __LINE__, pm, phw->phw_pmc));
	phw->phw_pmc = pm;

	return (0);
}

static int
riscv_describe(int cpu, int ri, struct pmc_info *pi, struct pmc **ppmc)
{
	char pmc_name[PMC_NAME_MAX];
	struct pmc_hw *phw;
	int error;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
		("[riscv,%d], illegal CPU %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < riscv_npmcs,
		("[riscv,%d] row-index %d out of range", __LINE__, ri));

	phw = &riscv_pcpu[cpu]->pc_riscvpmcs[ri];
	snprintf(pmc_name, sizeof(pmc_name), "RISCV-%d", ri);
	if ((error = copystr(pmc_name, pi->pm_name, PMC_NAME_MAX,
			     NULL)) != 0)
		return (error);
	pi->pm_class = PMC_CLASS_RISCV;
	if (phw->phw_state & PMC_PHW_FLAG_IS_ENABLED) {
		pi->pm_enabled = TRUE;
		*ppmc = phw->phw_pmc;
	} else {
		pi->pm_enabled = FALSE;
		*ppmc = NULL;
	}

	return (0);
}

static int
riscv_get_config(int cpu, int ri, struct pmc **ppm)
{

	*ppm = riscv_pcpu[cpu]->pc_riscvpmcs[ri].phw_pmc;

	return (0);
}

static int
riscv_read_pmc(int cpu, int ri, pmc_value_t *v)
{
	uint32_t config;
	struct pmc *pm;
	pmc_value_t start_val;
	pmc_value_t stop_val;
	pmc_value_t saved_val;
	pmc_value_t result;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
		("[riscv,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < riscv_npmcs,
		("[riscv,%d] illegal row index %d", __LINE__, ri));

	pm = riscv_pcpu[cpu]->pc_riscvpmcs[ri].phw_pmc;
	config = pm->pm_md.pm_riscv.pm_riscv_evsel;

	start_val = riscv_pcpu[cpu]->pc_start_values[config];
	if (pm->pm_state == PMC_STATE_STOPPED) {
		stop_val = riscv_pcpu[cpu]->pc_stop_values[config];
	} else {
		stop_val = csr_map[config].hpm_read();
	}

	if (start_val <= stop_val) {
		result = stop_val - start_val;
	} else {
		/* Assume all counter width 64bit */
		result = 0xffffffffffffffffUL;
		result -= start_val;
		result += stop_val;
	}

	saved_val = riscv_pcpu[cpu]->pc_saved_values[config];
	result += saved_val;

	PMCDBG2(MDP, REA, 2, "riscv-read id=%d -> %jd", ri, result);
	*v = result;

	return (0);
}

static int
riscv_write_pmc(int cpu, int ri, pmc_value_t v)
{
	uint32_t config;
	struct pmc *pm;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
		("[riscv,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < riscv_npmcs,
		("[riscv,%d] illegal row index %d", __LINE__, ri));

	pm = riscv_pcpu[cpu]->pc_riscvpmcs[ri].phw_pmc;
	config = pm->pm_md.pm_riscv.pm_riscv_evsel;

	PMCDBG3(MDP,WRI,1,"riscv-write cpu=%d ri=%d v=%jx", cpu, ri, v);
	riscv_pcpu[cpu]->pc_saved_values[config] = v;

	return (0);
}

static int
riscv_release_pmc(int cpu, int ri, struct pmc *pmc)
{
	struct pmc_hw *phw __unused;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
		("[riscv,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < riscv_npmcs,
		("[riscv,%d] illegal row-index %d", __LINE__, ri));

	phw = &riscv_pcpu[cpu]->pc_riscvpmcs[ri];
	KASSERT(phw->phw_pmc == NULL,
		("[riscv,%d] PHW pmc %p non-NULL", __LINE__, phw->phw_pmc));

	return (0);
}

static int
riscv_start_pmc(int cpu, int ri)
{

	struct pmc_hw *phw;
	uint32_t config;
	struct pmc *pm;

	phw    = &riscv_pcpu[cpu]->pc_riscvpmcs[ri];
	pm     = phw->phw_pmc;
	KASSERT(pm != NULL,
		("[riscv,%d] start unconfigured row-index %d", __LINE__, ri));
	config = pm->pm_md.pm_riscv.pm_riscv_evsel;

	/*
	 * XXX-AM: If sampling, we need to switch on profclock?
	 * This is required because we do not have good interrupt support from
	 * the HPM extensions, nor from the SBI interface with the firmware.
	 */

	/*
	 * XXX-AM: Currently we use the fixed mapping from BBL.
	 * In the future, counters may be configured using an mcall via an SBI
	 * extension.
	 */
	riscv_pcpu[cpu]->pc_start_values[config] = csr_map[config].hpm_read();

	return (0);
}

static int
riscv_stop_pmc(int cpu, int ri)
{
	uint32_t config;
	struct pmc_hw *phw;
	struct pmc *pm;

	phw    = &riscv_pcpu[cpu]->pc_riscvpmcs[ri];
	pm     = phw->phw_pmc;
	config = pm->pm_md.pm_riscv.pm_riscv_evsel;

	/*
	 * XXX-AM: Currently we use the fixed mapping from BBL.
	 * See riscv_start_pmc();
	 */
	riscv_pcpu[cpu]->pc_stop_values[config] = csr_map[config].hpm_read();

	return (0);
}

static int
riscv_pmc_switch_in(struct pmc_cpu *pc, struct pmc_process *pp)
{

	return (0);
}

static int
riscv_pmc_switch_out(struct pmc_cpu *pc, struct pmc_process *pp)
{

	return (0);
}

static int
riscv_pcpu_init(struct pmc_mdep *md, int cpu)
{
	struct riscv_pcpu *pac;
	struct pmc_hw  *phw;
	struct pmc_cpu *pc;
	int first_ri;
	int i;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[riscv,%d] wrong cpu number %d", __LINE__, cpu));
	PMCDBG1(MDP, INI, 1, "riscv-init cpu=%d", cpu);

	riscv_pcpu[cpu] = pac = malloc(sizeof(struct riscv_pcpu), M_PMC,
	    M_WAITOK | M_ZERO);

	pac->pc_riscvpmcs = malloc(sizeof(struct pmc_hw) * riscv_npmcs,
	    M_PMC, M_WAITOK | M_ZERO);
	pc = pmc_pcpu[cpu];
	first_ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_RISCV].pcd_ri;
	KASSERT(pc != NULL, ("[riscv,%d] NULL per-cpu pointer", __LINE__));

	for (i = 0, phw = pac->pc_riscvpmcs; i < riscv_npmcs; i++, phw++) {
		phw->phw_state    = PMC_PHW_FLAG_IS_ENABLED |
		    PMC_PHW_CPU_TO_STATE(cpu) | PMC_PHW_INDEX_TO_STATE(i);
		phw->phw_pmc      = NULL;
		pc->pc_hwpmcs[i + first_ri] = phw;
	}

	/* XXX manage mhpminhibit register? */
	return (0);
}

static int
riscv_pcpu_fini(struct pmc_mdep *md, int cpu)
{
	/* XXX manage mhpminhibit register? */

	return (0);
}

struct pmc_mdep *
pmc_md_initialize()
{
	struct pmc_mdep *pmc_mdep;
	struct pmc_classdep *pcd;

	riscv_npmcs = RISCV_NCOUNTERS;

	PMCDBG1(MDP,INI,1,"riscv-init npmcs=%d", riscv_npmcs);

	/*
	 * Allocate space for pointers to PMC HW descriptors and for
	 * the MDEP structure used by MI code.
	 */
	riscv_pcpu = malloc(sizeof(struct riscv_pcpu *) * pmc_cpu_max(), M_PMC,
			     M_WAITOK|M_ZERO);

	/* Just one class */
	pmc_mdep = pmc_mdep_alloc(1);

	snprintf(pmc_cpuid, sizeof(pmc_cpuid), "toooba");
	pmc_mdep->pmd_cputype = PMC_CPU_RISCV_CHERI_TOOOBA;
	csr_map = toooba_csr_map;

	pcd = &pmc_mdep->pmd_classdep[PMC_MDEP_CLASS_INDEX_RISCV];
	pcd->pcd_caps = TOOOBA_PMC_CAPS;
	pcd->pcd_class = PMC_CLASS_RISCV;
	pcd->pcd_num = riscv_npmcs;
	pcd->pcd_ri = pmc_mdep->pmd_npmc;
	pcd->pcd_width = 64;

	pcd->pcd_allocate_pmc   = riscv_allocate_pmc;
	pcd->pcd_config_pmc     = riscv_config_pmc;
	pcd->pcd_pcpu_fini      = riscv_pcpu_fini;
	pcd->pcd_pcpu_init      = riscv_pcpu_init;
	pcd->pcd_describe       = riscv_describe;
	pcd->pcd_get_config	= riscv_get_config;
	pcd->pcd_read_pmc       = riscv_read_pmc;
	pcd->pcd_write_pmc      = riscv_write_pmc;
	pcd->pcd_release_pmc    = riscv_release_pmc;
	pcd->pcd_start_pmc      = riscv_start_pmc;
	pcd->pcd_stop_pmc       = riscv_stop_pmc;

	pmc_mdep->pmd_intr       = NULL;
	pmc_mdep->pmd_switch_in  = riscv_pmc_switch_in;
	pmc_mdep->pmd_switch_out = riscv_pmc_switch_out;

	pmc_mdep->pmd_npmc += riscv_npmcs;

	return (pmc_mdep);
}

void
pmc_md_finalize(struct pmc_mdep *md)
{

	return;
}

/*
 * Note: Due to the lack of support for HPM register interrupts, the
 * only supported option is to hook the interrupt to profclock (which in turn
 * uses the RISC-V eventtimer backed by time/mtimecmp).
 * This is sad but unavoidable for now, unless we add a custom implementation
 * in our CHERI-TOOOBA cores.
 * The callchain sampling will then be a vailable for SOFT PMC.
 * XXX We may do something more direct by hooking directly in the RISC-V
 * interrupt handler and driving pmd_intr() directly from there. This would
 * still require profclock setup first from here though, in order to approximate
 * counter overflow interrupts.
 */

int
pmc_save_kernel_callchain(uintptr_t *cc, int nframes,
    struct trapframe *tf)
{
	struct unwind_state us;
	int depth = 1;

	us.sp = tf->tf_sp;
	us.fp = tf->tf_s[0];
	us.pc = tf->tf_ra;
	*cc++ = us.pc;

	while (depth < nframes) {
		if (!unwind_frame(curthread, &us))
			break;
		if (!PMC_IN_KERNEL((vm_offset_t)us.pc))
			break;
		*cc++ = us.pc;
		depth++;
	}

	return (depth);
}

int
pmc_save_user_callchain(uintptr_t *cc, int nframes,
    struct trapframe *tf)
{
	struct unwind_state us;
	int depth = 1;

	us.sp = tf->tf_sp;
	us.fp = tf->tf_s[0];
	us.pc = tf->tf_ra;
	*cc++ = us.pc;

	/* XXX-AM: not sure if it is ok for both hybrid and purecap userland */
	while (depth < nframes) {
		if (!unwind_frame(curthread, &us))
			break;
		if (!PMC_IN_USERSPACE((vm_offset_t)us.pc))
			break;
		*cc++ = us.pc;
		depth++;
	}

	return (depth);
}
