/*-
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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

#ifndef	_HWT_CORESIGHT_H_
#define	_HWT_CORESIGHT_H_

#define	TRCPRGCTLR		0x004 /* Trace Programming Control Register */
#define	 TRCPRGCTLR_EN		(1 << 0) /* Trace unit enable bit */
#define	TRCPROCSELR		0x008 /* Trace PE Select Control Register */
#define	TRCSTATR		0x00C /* Trace Trace Status Register */
#define	 TRCSTATR_PMSTABLE	(1 << 1) /* The programmers' model is stable. */
#define	 TRCSTATR_IDLE		(1 << 0) /* The trace unit is idle. */
#define	TRCCONFIGR		0x010 /* Trace Trace Configuration Register */
#define	 TRCCONFIGR_DV		(1 << 17) /* Data value tracing is enabled when INSTP0 is not 0b00 */
#define	 TRCCONFIGR_DA		(1 << 16) /* Data address tracing is enabled when INSTP0 is not 0b00. */
#define	 TRCCONFIGR_VMIDOPT	(1 << 15) /* Control bit to configure the Virtual context identifier value */
#define	 TRCCONFIGR_QE_S	13 /* Q element enable field */
#define	 TRCCONFIGR_QE_M	(0x3 << TRCCONFIGR_QE_S)
#define	 TRCCONFIGR_RS		(1 << 12) /* Return stack enable bit */
#define	 TRCCONFIGR_TS		(1 << 11) /* Global timestamp tracing is enabled. */
#define	 TRCCONFIGR_COND_S	8 /* Conditional instruction tracing bit. */
#define	 TRCCONFIGR_COND_M	(0x7 << TRCCONFIGR_COND_S)
#define	 TRCCONFIGR_COND_DIS	0
#define	 TRCCONFIGR_COND_LDR	(1 << TRCCONFIGR_COND_S) /* Conditional load instructions are traced. */
#define	 TRCCONFIGR_COND_STR	(2 << TRCCONFIGR_COND_S) /* Conditional store instructions are traced. */
#define	 TRCCONFIGR_COND_LDRSTR	(3 << TRCCONFIGR_COND_S) /* Conditional load and store instructions are traced. */
#define	 TRCCONFIGR_COND_ALL	(7 << TRCCONFIGR_COND_S) /* All conditional instructions are traced. */
#define	 TRCCONFIGR_VMID	(1 << 7) /* Virtual context identifier tracing is enabled. */
#define	 TRCCONFIGR_CID		(1 << 6) /* Context ID tracing is enabled. */
#define	 TRCCONFIGR_CCI		(1 << 4) /* Cycle counting in the instruction trace is enabled. */
#define	 TRCCONFIGR_BB		(1 << 3) /* Branch broadcast mode is enabled. */
#define	 TRCCONFIGR_INSTP0_S	1 /* Instruction P0 field. */
#define	 TRCCONFIGR_INSTP0_M	(0x3 << TRCCONFIGR_INSTP0_S)
#define	 TRCCONFIGR_INSTP0_NONE	0 /* Do not trace load and store instructions as P0 instructions. */
#define	 TRCCONFIGR_INSTP0_LDR	(1 << TRCCONFIGR_INSTP0_S) /* Trace load instructions as P0 instructions. */
#define	 TRCCONFIGR_INSTP0_STR	(2 << TRCCONFIGR_INSTP0_S) /* Trace store instructions as P0 instructions. */
#define	 TRCCONFIGR_INSTP0_LDRSTR (3 << TRCCONFIGR_INSTP0_S) /* Trace load and store instructions as P0 instr. */
#define	TRCAUXCTLR		0x018 /* Trace Auxiliary Control Register */
#define	TRCEVENTCTL0R		0x020 /* Trace Event Control 0 Register */
#define	TRCEVENTCTL1R		0x024 /* Trace Event Control 1 Register */
#define	TRCSTALLCTLR		0x02C /* Trace Stall Control Register */
#define	TRCTSCTLR		0x030 /* Trace Global Timestamp Control Register */
#define	TRCSYNCPR		0x034 /* Trace Synchronization Period Register */
#define	 TRCSYNCPR_PERIOD_S	0
#define	 TRCSYNCPR_PERIOD_M	0x1f
#define	 TRCSYNCPR_1K		(10 << TRCSYNCPR_PERIOD_S)
#define	 TRCSYNCPR_2K		(11 << TRCSYNCPR_PERIOD_S)
#define	 TRCSYNCPR_4K		(12 << TRCSYNCPR_PERIOD_S)
#define	TRCCCCTLR		0x038 /* Trace Cycle Count Control Register */
#define	TRCBBCTLR		0x03C /* Trace Branch Broadcast Control Register */
#define	TRCTRACEIDR		0x040 /* Trace Trace ID Register */
#define	TRCQCTLR		0x044 /* Trace Q Element Control Register */
#define	 TRCQCTLR_MODE_INC	(1 << 8) /* Include mode. */
#define	TRCVICTLR		0x080 /* Trace ViewInst Main Control Register */
#define	 TRCVICTLR_SSSTATUS	(1 << 9) /* The start/stop logic is in the started state. */
#define	 TRCVICTLR_EXLEVEL_NS_S	20
#define	 TRCVICTLR_EXLEVEL_NS_M	(0xf << TRCVICTLR_EXLEVEL_NS_S)
#define	 TRCVICTLR_EXLEVEL_NS(n) (0x1 << ((n) + TRCVICTLR_EXLEVEL_NS_S))
#define	 TRCVICTLR_EXLEVEL_S_S	16
#define	 TRCVICTLR_EXLEVEL_S_M	(0xf << TRCVICTLR_EXLEVEL_S_S)
#define	 TRCVICTLR_EXLEVEL_S(n)	(0x1 << ((n) + TRCVICTLR_EXLEVEL_S_S))
#define	 EVENT_SEL_S		0
#define	 EVENT_SEL_M		(0x1f << EVENT_SEL_S)
#define	TRCVIIECTLR		0x084 /* Trace ViewInst Include/Exclude Control Register */
#define	 TRCVIIECTLR_INCLUDE_S	0
#define	TRCVISSCTLR		0x088 /* Trace ViewInst Start/Stop Control Register */
#define	TRCVIPCSSCTLR		0x08C /* Trace ViewInst Start/Stop PE Comparator Control Register */
#define	TRCVDCTLR		0x0A0 /* Trace ViewData Main Control Register */
#define	 TRCVDCTLR_TRCEXDATA	(1 << 12) /* Exception and exception return data transfers are traced */
#define	 TRCVDCTLR_TBI		(1 << 11) /* The trace unit assigns bits[63:56] to have the same value as bits[63:56] of the data address. */
#define	 TRCVDCTLR_PCREL	(1 << 10) /* The trace unit does not trace the address or value portions of PC-relative transfers. */
#define	 TRCVDCTLR_SPREL_S	8
#define	 TRCVDCTLR_SPREL_M	(0x3 << TRCVDCTLR_SPREL_S)
#define	 TRCVDCTLR_EVENT_S	0
#define	 TRCVDCTLR_EVENT_M	(0xff << TRCVDCTLR_EVENT_S)
#define	TRCVDSACCTLR		0x0A4 /* Trace ViewData Include/Exclude Single Address Comparator Control Register */
#define	TRCVDARCCTLR		0x0A8 /* Trace ViewData Include/Exclude Address Range Comparator Control Register */
#define	TRCSEQEVR(n)		(0x100 + (n) * 0x4)	/* Trace Sequencer State Transition Control Register [n=0-2] */
#define	TRCSEQRSTEVR		0x118 /* Trace Sequencer Reset Control Register */
#define	TRCSEQSTR		0x11C /* Trace Sequencer State Register */
#define	TRCEXTINSELR		0x120 /* Trace External Input Select Register */
#define	TRCCNTRLDVR(n)		(0x140 + (n) * 0x4) /* 32 Trace Counter Reload Value Register [n=0-3] */
#define	TRCCNTCTLR(n)		(0x150 + (n) * 0x4) /* 32 Trace Counter Control Register [n=0-3] */
#define	TRCCNTVR(n)		(0x160 + (n) * 0x4) /* 32 Trace Counter Value Register [n=0-3] */
#define	TRCIMSPEC(n)		(0x1C0 + (n) * 0x4)	/* Trace IMPLEMENTATION DEFINED register [n=0-7] */

#define	TRCIDR0(n)		(0x1E0 + 0x4 * (n))
#define	TRCIDR8(n)		(0x180 + 0x4 * (n))
#define	TRCIDR(n)		((n > 7) ? TRCIDR8(n) : TRCIDR0(n))
#define	 TRCIDR1_TRCARCHMAJ_S	8
#define	 TRCIDR1_TRCARCHMAJ_M	(0xf << TRCIDR1_TRCARCHMAJ_S)
#define	 TRCIDR1_TRCARCHMIN_S	4
#define	 TRCIDR1_TRCARCHMIN_M	(0xf << TRCIDR1_TRCARCHMIN_S)

#define	TRCRSCTLR(n)		(0x200 + (n) * 0x4) /* Trace Resource Selection Control Register [n=2-31] */
#define	TRCSSCCR(n)		(0x280 + (n) * 0x4) /* Trace Single-shot Comparator Control Register [n=0-7] */
#define	TRCSSCSR(n)		(0x2A0 + (n) * 0x4) /* Trace Single-shot Comparator Status Register [n=0-7] */
#define	TRCSSPCICR(n)		(0x2C0 + (n) * 0x4) /* Trace Single-shot PE Comparator Input Control [n=0-7] */
#define	TRCOSLAR		0x300 /* Management OS Lock Access Register */
#define	TRCOSLSR		0x304 /* Management OS Lock Status Register */
#define	TRCPDCR			0x310 /* Management PowerDown Control Register */
#define	TRCPDSR			0x314 /* Management PowerDown Status Register */
#define	TRCACVR(n)		(0x400 + (n) * 0x8) /* Trace Address Comparator Value Register [n=0-15] */
#define	TRCACATR(n)		(0x480 + (n) * 0x8) /* Trace Address Comparator Access Type Register [n=0-15] */
#define	 TRCACATR_DTBM		(1 << 21)
#define	 TRCACATR_DATARANGE	(1 << 20)
#define	 TRCACATR_DATASIZE_S	18
#define	 TRCACATR_DATASIZE_M	(0x3 << TRCACATR_DATASIZE_S)
#define	 TRCACATR_DATASIZE_B	(0x0 << TRCACATR_DATASIZE_S)
#define	 TRCACATR_DATASIZE_HW	(0x1 << TRCACATR_DATASIZE_S)
#define	 TRCACATR_DATASIZE_W	(0x2 << TRCACATR_DATASIZE_S)
#define	 TRCACATR_DATASIZE_DW	(0x3 << TRCACATR_DATASIZE_S)
#define	 TRCACATR_DATAMATCH_S	16
#define	 TRCACATR_DATAMATCH_M	(0x3 << TRCACATR_DATAMATCH_S)
#define	 TRCACATR_EXLEVEL_S_S	8
#define	 TRCACATR_EXLEVEL_S_M	(0xf << TRCACATR_EXLEVEL_S_S)
#define	 TRCACATR_EXLEVEL_S(n)	(0x1 << ((n) + TRCACATR_EXLEVEL_S_S))
#define	 TRCACATR_EXLEVEL_NS_S	12
#define	 TRCACATR_EXLEVEL_NS_M	(0xf << TRCACATR_EXLEVEL_NS_S)
#define	 TRCACATR_EXLEVEL_NS(n)	(0x1 << ((n) + TRCACATR_EXLEVEL_NS_S))
#define	TRCDVCVR(n)		(0x500 + (n) * 0x8) /* Trace Data Value Comparator Value Register [n=0-7] */
#define	TRCDVCMR(n)		(0x580 + (n) * 0x8) /* Trace Data Value Comparator Mask Register [n=0-7] */
#define	TRCCIDCVR(n)		(0x600 + (n) * 0x8) /* Trace Context ID Comparator Value Register [n=0-7] */
#define	TRCVMIDCVR(n)		(0x640 + (n) * 0x8) /* Trace Virtual context identifier Comparator Value [n=0-7] */
#define	TRCCIDCCTLR0		0x680 /* Trace Context ID Comparator Control Register 0 */
#define	TRCCIDCCTLR1		0x684 /* Trace Context ID Comparator Control Register 1 */
#define	TRCVMIDCCTLR0		0x688 /* Trace Virtual context identifier Comparator Control Register 0 */
#define	TRCVMIDCCTLR1		0x68C /* Trace Virtual context identifier Comparator Control Register 1 */
#define	TRCITCTRL		0xF00 /* Management Integration Mode Control register */
#define	TRCCLAIMSET		0xFA0 /* Trace Claim Tag Set register */
#define	TRCCLAIMCLR		0xFA4 /* Trace Claim Tag Clear register */
#define	TRCDEVAFF0		0xFA8 /* Management Device Affinity register 0 */
#define	TRCDEVAFF1		0xFAC /* Management Device Affinity register 1 */
#define	TRCLAR			0xFB0 /* Management Software Lock Access Register */
#define	TRCLSR			0xFB4 /* Management Software Lock Status Register */
#define	TRCAUTHSTATUS		0xFB8 /* Management Authentication Status register */
#define	TRCDEVARCH		0xFBC /* Management Device Architecture register */
#define	TRCDEVID		0xFC8 /* Management Device ID register */
#define	TRCDEVTYPE		0xFCC /* Management Device Type register */
#define	TRCPIDR4		0xFD0 /* Management Peripheral ID4 Register */
#define	TRCPIDR(n)		(0xFE0 + (n) * 0x4)	/* Management Peripheral IDn Register [n=0-3] */
#define	TRCPIDR567(n)		(0xFD4 + ((n) - 5) * 0x4) /*  Management Peripheral ID5 to Peripheral ID7 Registers */
#define	TRCCIDR(n)		(0xFF0 + (n) * 0x4)	/* Management Component IDn Register [n=0-4] */

/* ETMv4 resources */
#define ETM_MAX_NR_PE			8
#define ETMv4_MAX_CNTR			4
#define ETM_MAX_SEQ_STATES		4
#define ETM_MAX_EXT_INP_SEL		4
#define ETM_MAX_EXT_INP			256
#define ETM_MAX_EXT_OUT			4
#define ETM_MAX_SINGLE_ADDR_CMP		16
#define ETM_MAX_ADDR_RANGE_CMP		(ETM_MAX_SINGLE_ADDR_CMP / 2)
#define ETM_MAX_DATA_VAL_CMP		8
#define ETMv4_MAX_CTXID_CMP		8
#define ETM_MAX_VMID_CMP		8
#define ETM_MAX_PE_CMP			8
#define ETM_MAX_RES_SEL			32
#define ETM_MAX_SS_CMP			8

/**
 * struct etmv4_config - configuration information related to an ETMv4
 * @mode:	Controls various modes supported by this ETM.
 * @pe_sel:	Controls which PE to trace.
 * @cfg:	Controls the tracing options.
 * @eventctrl0: Controls the tracing of arbitrary events.
 * @eventctrl1: Controls the behavior of the events that @event_ctrl0 selects.
 * @stallctl:	If functionality that prevents trace unit buffer overflows
 *		is available.
 * @ts_ctrl:	Controls the insertion of global timestamps in the
 *		trace streams.
 * @syncfreq:	Controls how often trace synchronization requests occur.
 *		the TRCCCCTLR register.
 * @ccctlr:	Sets the threshold value for cycle counting.
 * @vinst_ctrl:	Controls instruction trace filtering.
 * @viiectlr:	Set or read, the address range comparators.
 * @vissctlr:	Set, or read, the single address comparators that control the
 *		ViewInst start-stop logic.
 * @vipcssctlr:	Set, or read, which PE comparator inputs can control the
 *		ViewInst start-stop logic.
 * @seq_idx:	Sequencor index selector.
 * @seq_ctrl:	Control for the sequencer state transition control register.
 * @seq_rst:	Moves the sequencer to state 0 when a programmed event occurs.
 * @seq_state:	Set, or read the sequencer state.
 * @cntr_idx:	Counter index seletor.
 * @cntrldvr:	Sets or returns the reload count value for a counter.
 * @cntr_ctrl:	Controls the operation of a counter.
 * @cntr_val:	Sets or returns the value for a counter.
 * @res_idx:	Resource index selector.
 * @res_ctrl:	Controls the selection of the resources in the trace unit.
 * @ss_idx:	Single-shot index selector.
 * @ss_ctrl:	Controls the corresponding single-shot comparator resource.
 * @ss_status:	The status of the corresponding single-shot comparator.
 * @ss_pe_cmp:	Selects the PE comparator inputs for Single-shot control.
 * @addr_idx:	Address comparator index selector.
 * @addr_val:	Value for address comparator.
 * @addr_acc:	Address comparator access type.
 * @addr_type:	Current status of the comparator register.
 * @ctxid_idx:	Context ID index selector.
 * @ctxid_pid:	Value of the context ID comparator.
 * @ctxid_mask0:Context ID comparator mask for comparator 0-3.
 * @ctxid_mask1:Context ID comparator mask for comparator 4-7.
 * @vmid_idx:	VM ID index selector.
 * @vmid_val:	Value of the VM ID comparator.
 * @vmid_mask0:	VM ID comparator mask for comparator 0-3.
 * @vmid_mask1:	VM ID comparator mask for comparator 4-7.
 * @ext_inp:	External input selection.
 * @s_ex_level: Secure ELs where tracing is supported.
 */

struct etmv4_config {
	uint32_t		mode;
	uint32_t		pe_sel;
	uint32_t		cfg;
	uint32_t		eventctrl0;
	uint32_t		eventctrl1;
	uint32_t		stall_ctrl;
	uint32_t		ts_ctrl;
	uint32_t		syncfreq;
	uint32_t		ccctlr;
	uint32_t		bb_ctrl;
	uint32_t		vinst_ctrl;
	uint32_t		viiectlr;
	uint32_t		vissctlr;
	uint32_t		vipcssctlr;
	uint8_t			seq_idx;
	uint32_t		seq_ctrl[ETM_MAX_SEQ_STATES];
	uint32_t		seq_rst;
	uint32_t		seq_state;
	uint8_t			cntr_idx;
	uint32_t		cntrldvr[ETMv4_MAX_CNTR];
	uint32_t		cntr_ctrl[ETMv4_MAX_CNTR];
	uint32_t		cntr_val[ETMv4_MAX_CNTR];
	uint8_t			res_idx;
	uint32_t		res_ctrl[ETM_MAX_RES_SEL];
	uint8_t			ss_idx;
	uint32_t		ss_ctrl[ETM_MAX_SS_CMP];
	uint32_t		ss_status[ETM_MAX_SS_CMP];
	uint32_t		ss_pe_cmp[ETM_MAX_SS_CMP];
	uint8_t			addr_idx;
	uint64_t		addr_val[ETM_MAX_SINGLE_ADDR_CMP];
	uint64_t		addr_acc[ETM_MAX_SINGLE_ADDR_CMP];
	uint8_t			addr_type[ETM_MAX_SINGLE_ADDR_CMP];
	uint8_t			ctxid_idx;
	uint64_t		ctxid_pid[ETMv4_MAX_CTXID_CMP];
	uint32_t		ctxid_mask0;
	uint32_t		ctxid_mask1;
	uint8_t			vmid_idx;
	uint64_t		vmid_val[ETM_MAX_VMID_CMP];
	uint32_t		vmid_mask0;
	uint32_t		vmid_mask1;
	uint32_t		ext_inp;
	uint8_t			s_ex_level;
};

extern struct trace_dev_methods cs_methods;

#endif /* !_HWT_CORESIGHT_H_ */
