/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
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

/* ARM CoreSight tracing unit. */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/cpuset.h>
#include <sys/hwt.h>
#include <sys/wait.h>
#include <sys/sysctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <stdio.h>
#include <string.h>

#include <opencsd/c_api/ocsd_c_api_types.h>
#include <opencsd/c_api/opencsd_c_api.h>

#include "hwt.h"
#include "hwt_coresight.h"

#include "libpmcstat_stubs.h"
#include <libpmcstat.h>
#include <libxo/xo.h>

#define	HWT_CORESIGHT_DEBUG
#undef	HWT_CORESIGHT_DEBUG

#ifdef	HWT_CORESIGHT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static int cs_flags = 0;
#define	FLAG_FORMAT			(1 << 0)
#define	FLAG_FRAME_RAW_UNPACKED		(1 << 1)
#define	FLAG_FRAME_RAW_PACKED		(1 << 2)

#define	PACKET_STR_LEN	1024
static char packet_str[PACKET_STR_LEN];

struct cs_decoder {
	dcd_tree_handle_t dcdtree_handle;
	struct trace_context *tc;
	int dp_ret;
	int cpu_id;
	FILE *out;
	xo_handle_t *xop;
};

static ocsd_err_t
attach_raw_printers(dcd_tree_handle_t dcd_tree_h)
{
	ocsd_err_t err;
	int flags;

	flags = 0;
	err = OCSD_OK;

	if (cs_flags & FLAG_FRAME_RAW_UNPACKED)
		flags |= OCSD_DFRMTR_UNPACKED_RAW_OUT;

	if (cs_flags & FLAG_FRAME_RAW_PACKED)
		flags |= OCSD_DFRMTR_PACKED_RAW_OUT;

	if (flags)
		err = ocsd_dt_set_raw_frame_printer(dcd_tree_h, flags);

	return err;
}

static int
print_data_array(const uint8_t *p_array, const int array_size,
    char *p_buffer, int buf_size)
{
	int bytes_processed;
	int chars_printed;

	chars_printed = 0;
	p_buffer[0] = 0;

	if (buf_size > 9) {
		strcat(p_buffer, "[ ");
		chars_printed += 2;

		for (bytes_processed = 0; bytes_processed < array_size;
		    bytes_processed++) {
			sprintf(p_buffer + chars_printed, "0x%02X ",
			    p_array[bytes_processed]);
			chars_printed += 5;
			if ((chars_printed + 5) > buf_size)
				break;
		}

		strcat(p_buffer, "];");
		chars_printed += 2;
	} else if (buf_size >= 4) {
		sprintf(p_buffer, "[];");
		chars_printed += 3;
	}

	return (chars_printed);
}

static void
packet_monitor(void *context __unused,
    const ocsd_datapath_op_t op,
    const ocsd_trc_index_t index_sop,
    const void *p_packet_in,
    const uint32_t size,
    const uint8_t *p_data)
{
	int offset;

	offset = 0;

	switch (op) {
	case OCSD_OP_DATA:
		sprintf(packet_str, "Idx:%"  OCSD_TRC_IDX_STR ";", index_sop);
		offset = strlen(packet_str);
		offset += print_data_array(p_data, size, packet_str + offset,
		    PACKET_STR_LEN - offset);

		/*
		 * Got a packet -- convert to string and use the libraries'
		 * message output to print to file and stdoout
		 */

		if (ocsd_pkt_str(OCSD_PROTOCOL_ETMV4I, p_packet_in,
		    packet_str + offset, PACKET_STR_LEN - offset) == OCSD_OK) {
			/* add in <CR> */
			if (strlen(packet_str) == PACKET_STR_LEN - 1)/*maxlen*/
				packet_str[PACKET_STR_LEN - 2] = '\n';
			else
				strcat(packet_str,"\n");

			/* print it using the library output logger. */
			ocsd_def_errlog_msgout(packet_str);
		}
		break;

	case OCSD_OP_EOT:
		sprintf(packet_str,"**** END OF TRACE ****\n");
		ocsd_def_errlog_msgout(packet_str);
		break;
	default:
		printf("%s: unknown op %d\n", __func__, op);
		break;
	}
}

static ocsd_err_t
create_test_memory_acc(dcd_tree_handle_t handle, struct trace_context *tc)
{
	ocsd_vaddr_t address;
	uint8_t *p_mem_buffer;
	uint32_t mem_length;
#ifdef HWT_CORESIGHT_DEBUG
	uint64_t *t;
#endif
	int ret;

	dprintf("%s\n", __func__);

	address = (ocsd_vaddr_t)tc->base;

#ifdef HWT_CORESIGHT_DEBUG
	t = (uint64_t *)tc->base;
	printf("%lx %lx %lx %lx\n", t[0], t[1], t[2], t[3]);
#endif

	p_mem_buffer = (uint8_t *)tc->base;
	mem_length = tc->bufsize;

	ret = ocsd_dt_add_buffer_mem_acc(handle, address,
	    OCSD_MEM_SPACE_ANY, p_mem_buffer, mem_length);
	if (ret != OCSD_OK) {
		printf("%s: can't create memory accessor: ret %d\n",
		    __func__, ret);
		return (ENXIO);
	}

	return (ret);
}

static ocsd_err_t
create_generic_decoder(dcd_tree_handle_t handle, const char *p_name,
    const void *p_cfg, const void *p_context __unused,
    struct trace_context *tc)
{
	ocsd_err_t ret;
	uint8_t CSID;

	CSID = 0;

	dprintf("%s\n", __func__);

	ret = ocsd_dt_create_decoder(handle, p_name,
	    OCSD_CREATE_FLG_FULL_DECODER, p_cfg, &CSID);
	if (ret != OCSD_OK)
		return (-1);

	printf("%s: CSID to decode: %d.\n", __func__, CSID);

	if (cs_flags & FLAG_FORMAT) {
		ret = ocsd_dt_attach_packet_callback(handle, CSID,
		    OCSD_C_API_CB_PKT_MON, packet_monitor, p_context);
		if (ret != OCSD_OK)
			return (-1);
	}

	/* attach a memory accessor */
	ret = create_test_memory_acc(handle, tc);
	if (ret != OCSD_OK) {
		ocsd_dt_remove_decoder(handle, CSID);
		return (ENXIO);
	}

	return (ret);
}

static ocsd_err_t
create_decoder_etmv4(struct trace_context *tc, dcd_tree_handle_t dcd_tree_h,
    int thread_id)
{
	struct etmv4_config *config;
	ocsd_etmv4_cfg trace_config;
	uint32_t id_regs[14];
	size_t regsize;
	ocsd_err_t ret;
	char name[32];
	int error;
	int i;

	config = tc->config;

	trace_config.arch_ver = ARCH_V8;
	trace_config.core_prof = profile_CortexA;
	trace_config.reg_configr = config->cfg;
	/* TODO: take thread_id from config ? */
	trace_config.reg_traceidr = thread_id + 1;

	for (i = 0; i < 14; i++) {
		snprintf(name, 32, "dev.coresight_etm4x.0.idr%d", i);
		regsize = sizeof(id_regs[i]);
		error = sysctlbyname(name, &id_regs[i], &regsize, NULL, 0);
		if (error) {
			printf("Error: could not query ETMv4\n");
			return (error);
		}
	}

	trace_config.reg_idr0 = id_regs[0];
	trace_config.reg_idr1 = id_regs[1];
	trace_config.reg_idr2 = id_regs[2];
	trace_config.reg_idr8 = id_regs[8];
	trace_config.reg_idr9 = id_regs[9];
	trace_config.reg_idr10 = id_regs[10];
	trace_config.reg_idr11 = id_regs[11];
	trace_config.reg_idr12 = id_regs[12];
	trace_config.reg_idr13 = id_regs[13];

	/* Instruction decoder. */
	ret = create_generic_decoder(dcd_tree_h, OCSD_BUILTIN_DCD_ETMV4I,
	    (void *)&trace_config, 0, tc);

	return (ret);
}

static int
cs_process_chunk_raw(struct trace_context *tc, size_t start, size_t len,
    uint32_t *consumed)
{
	void *base;

	base = (void *)((uintptr_t)tc->base + (uintptr_t)start);

	fwrite(base, len, 1, tc->raw_f);
	fflush(tc->raw_f);

	*consumed = len;

	return (0);
}

static int
cs_process_chunk(struct trace_context *tc, struct cs_decoder *dec,
    size_t start, size_t len, uint32_t *consumed)
{
	void *base;
	int error;

	/* Coresight data is always on first cpu cdev due to funnelling by HW.*/
	base = (void *)((uintptr_t)tc->base + (uintptr_t)start);

	dprintf("Processing data for CPU%d\n", dec->cpu_id);

	error = ocsd_dt_process_data(dec->dcdtree_handle,
	    OCSD_OP_DATA, start, len, base, consumed);

	if (*consumed != len) {
		printf("error");
		exit(5);
	}

	return (error);
}

struct pmcstat_pcmap *
pmcstat_process_find_map(struct pmcstat_process *p, uintfptr_t pc)
{
	struct pmcstat_pcmap *ppm;

	TAILQ_FOREACH(ppm, &p->pp_map, ppm_next) {
		if (pc >= ppm->ppm_lowpc && pc < ppm->ppm_highpc)
			return (ppm);
		if (pc < ppm->ppm_lowpc)
			return (NULL);
	}

	return (NULL);
}

static struct pmcstat_symbol *
symbol_lookup(const struct trace_context *tc, uint64_t ip,
    struct pmcstat_image **img, uint64_t *newpc0)
{
	struct pmcstat_image *image;
	struct pmcstat_symbol *sym;
	struct pmcstat_pcmap *map;
	uint64_t newpc;

	map = pmcstat_process_find_map(tc->pp, ip);
	if (map != NULL) {
		image = map->ppm_image;
		newpc = ip - ((unsigned long)map->ppm_lowpc +
		    (image->pi_vaddr - image->pi_start));
		sym = pmcstat_symbol_search(image, newpc); /* Could be NULL. */
		newpc += image->pi_vaddr;

		*img = image;
		*newpc0 = newpc;

		return (sym);
	} else
		*img = NULL;

        return (NULL);
}

static void __unused
print_timestamp(const ocsd_generic_trace_elem *elem)
{
	char ts[100];

	if (elem->timestamp != 0)
		sprintf(ts, "ts %ld", elem->timestamp);
	else
		sprintf(ts, "                  ");
}

static ocsd_datapath_resp_t
gen_trace_elem_print_lookup(const void *p_context,
    const ocsd_trc_index_t index_sop __unused,
    const uint8_t trc_chan_id __unused,
    const ocsd_generic_trace_elem *elem)
{
	struct trace_context *tc;
	struct pmcstat_image *image;
	ocsd_datapath_resp_t resp;
	struct pmcstat_symbol *sym;
	unsigned long offset;
	const struct cs_decoder *dec;
	const char *piname;
	const char *psname;
	uint64_t newpc;
	uint64_t ip;
	FILE *out;

	dec = (const struct cs_decoder *)p_context;
	tc = dec->tc;
	out = dec->out;

	resp = OCSD_RESP_CONT;

	dprintf("%s: Idx:%d ELEM TYPE %d, st_addr %lx, en_addr %lx\n",
	    __func__, index_sop, elem->elem_type,
	    elem->st_addr, elem->en_addr);

	if (elem->st_addr <= 0)
		return (resp);

	ip = elem->st_addr;

	sym = symbol_lookup(tc, ip, &image, &newpc);

	static const char *ARMv8Excep[] = {
		"PE Reset", "Debug Halt", "Call", "Trap",
		"System Error", "Reserved", "Inst Debug", "Data Debug",
		"Reserved", "Reserved", "Alignment", "Inst Fault",
		"Data Fault", "Reserved", "IRQ", "FIQ"
	};

	switch (elem->elem_type) {
	case OCSD_GEN_TRC_ELEM_UNKNOWN:
		fprintf(out, "Unknown packet.\n");
		return (resp);
	case OCSD_GEN_TRC_ELEM_NO_SYNC:
		fprintf(out, "No sync.\n");
		return (resp);
	case OCSD_GEN_TRC_ELEM_TRACE_ON:
		/* fprintf(out, "Trace on.\n"); */
		return (resp);
	case OCSD_GEN_TRC_ELEM_EO_TRACE:
		fprintf(out, "End of Trace.\n");
		return (resp);
	case OCSD_GEN_TRC_ELEM_PE_CONTEXT:
		break;
	case OCSD_GEN_TRC_ELEM_INSTR_RANGE:
	case OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH:
		return (resp);
	case OCSD_GEN_TRC_ELEM_ADDR_NACC:
		break;
	case OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN:
		return (resp);
	case OCSD_GEN_TRC_ELEM_EXCEPTION:
		fprintf(out, "Exception #%d (%s)\n", elem->exception_number,
		    ARMv8Excep[elem->exception_number]);
		return (resp);
	case OCSD_GEN_TRC_ELEM_EXCEPTION_RET:
		fprintf(out, "Exception RET to %lx\n", elem->st_addr);
		return (resp);
	case OCSD_GEN_TRC_ELEM_TIMESTAMP:
		fprintf(out, "Timestamp: %lx\n", elem->timestamp);
		return (resp);
	case OCSD_GEN_TRC_ELEM_CYCLE_COUNT:
		fprintf(out, "Cycle count: %d\n", elem->cycle_count);
		return (resp);
	case OCSD_GEN_TRC_ELEM_EVENT:
	case OCSD_GEN_TRC_ELEM_SWTRACE:
	case OCSD_GEN_TRC_ELEM_SYNC_MARKER:
	case OCSD_GEN_TRC_ELEM_MEMTRANS:
	case OCSD_GEN_TRC_ELEM_INSTRUMENTATION:
	case OCSD_GEN_TRC_ELEM_CUSTOM:
		return (resp);
	};


	if (sym || image) {
		xo_open_instance("entry");
		xo_emit_h(dec->xop, "{:pc/pc 0x%08lx/%x}", ip);
		xo_emit_h(dec->xop, " ");
	}

	if (image) {
		if (tc->mode == HWT_MODE_THREAD) {
			xo_emit_h(dec->xop, "{:newpc/(%lx)/%x}", newpc);
			xo_emit_h(dec->xop, "\t");
		}

		piname = pmcstat_string_unintern(image->pi_name);
		xo_emit_h(dec->xop, "{:piname/%12s/%s}", piname);
	}

	if (sym) {
		psname = pmcstat_string_unintern(sym->ps_name);
		offset = newpc - (sym->ps_start + image->pi_vaddr);
		xo_emit_h(dec->xop, "\t");
		xo_emit_h(dec->xop, "{:psname/%s/%s}", psname);
		xo_emit_h(dec->xop, "{:offset/+0x%lx/%ju}", offset);
	}

	if (sym || image) {
		xo_emit_h(dec->xop, "\n");
		xo_close_instance("entry");
	}

	xo_flush();

	return (resp);
}

static int
hwt_coresight_init(struct trace_context *tc, struct cs_decoder *dec,
    int thread_id)
{
	char filename[MAXPATHLEN];
	int error;

	dec->cpu_id = thread_id;
	dec->tc = tc;
	dec->dp_ret = OCSD_RESP_CONT;
	dec->dcdtree_handle = ocsd_create_dcd_tree(OCSD_TRC_SRC_FRAME_FORMATTED,
	    OCSD_DFRMTR_FRAME_MEM_ALIGN);
	if (dec->dcdtree_handle == C_API_INVALID_TREE_HANDLE) {
		printf("can't find dcd tree\n");
		return (-1);
	}

	if (tc->filename) {
		if (tc->mode == HWT_MODE_CPU)
			snprintf(filename, MAXPATHLEN, "%s%d", tc->filename,
			    dec->cpu_id);
		else
			snprintf(filename, MAXPATHLEN, "%s", tc->filename);

		dec->out = fopen(filename, "w");
		if (dec->out == NULL) {
			printf("could not open %s\n", filename);
			return (ENXIO);
		}
		dec->xop = xo_create_to_file(dec->out, XO_STYLE_TEXT, XOF_WARN);
	} else {
		dec->out = stdout;
		dec->xop = NULL;
	}

	if (tc->flag_format)
		cs_flags |= FLAG_FORMAT;

#if 0
	cs_flags |= FLAG_FRAME_RAW_UNPACKED;
	cs_flags |= FLAG_FRAME_RAW_PACKED;
#endif

	error = create_decoder_etmv4(tc, dec->dcdtree_handle, thread_id);
	if (error != OCSD_OK) {
		printf("can't create decoder: tc->base %p\n", tc->base);
		return (-2);
	}

#ifdef HWT_CORESIGHT_DEBUG
	ocsd_tl_log_mapped_mem_ranges(dec->dcdtree_handle);
#endif

	if (cs_flags & FLAG_FORMAT)
		ocsd_dt_set_gen_elem_printer(dec->dcdtree_handle);
	else
		ocsd_dt_set_gen_elem_outfn(dec->dcdtree_handle,
		    gen_trace_elem_print_lookup, dec);

	attach_raw_printers(dec->dcdtree_handle);

	return (0);
}

static void
hwt_coresight_fill_config(struct trace_context *tc, struct etmv4_config *config)
{
	int excp_level;
	uint32_t reg;
	uint32_t val;
	int i;

	memset(config, 0, sizeof(struct etmv4_config));

	reg = TRCCONFIGR_RS | TRCCONFIGR_TS;
	reg |= TRCCONFIGR_CID | TRCCONFIGR_VMID;
	reg |= TRCCONFIGR_COND_DIS;
	config->cfg = reg;

	config->ts_ctrl = 0;
	config->syncfreq = TRCSYNCPR_4K;

	if (tc->mode == HWT_MODE_THREAD)
		excp_level = 0; /* User mode. */
	else
		excp_level = 1; /* CPU mode. */

	reg = TRCVICTLR_SSSTATUS;
	reg |= (1 << EVENT_SEL_S);
	reg |= TRCVICTLR_EXLEVEL_NS(1 << excp_level);
	reg |= TRCVICTLR_EXLEVEL_S(1 << excp_level);
	config->vinst_ctrl = reg;

	/* Address-range filtering. */
	val = 0;
	for (i = 0; i < tc->nranges * 2; i++) {
		config->addr_val[i] = tc->addr_ranges[i];

		reg = TRCACATR_EXLEVEL_S(1 << excp_level);
		reg |= TRCACATR_EXLEVEL_NS(1 << excp_level);
		config->addr_acc[i] = reg;

		/* Include the range ID. */
		val |= (1 << (TRCVIIECTLR_INCLUDE_S + i / 2));
	}
	config->viiectlr = val;
}

static int
hwt_coresight_set_config(struct trace_context *tc)
{
	struct hwt_set_config sconf;
	struct etmv4_config *config;
	int error;

	config = malloc(sizeof(struct etmv4_config));
	hwt_coresight_fill_config(tc, config);

	tc->config = config;

	sconf.config = config;
	sconf.config_size = sizeof(struct etmv4_config);
	sconf.config_version = 1;
	sconf.pause_on_mmap = tc->suspend_on_mmap ? 1 : 0;

	error = ioctl(tc->thr_fd, HWT_IOC_SET_CONFIG, &sconf);

	return (error);
}

static int
cs_process_chunk1(struct trace_context *tc, struct cs_decoder *dec,
    size_t cursor, size_t len, uint32_t *processed)
{
	int cpu_id;
	int error;

	if (tc->raw) {
		error = cs_process_chunk_raw(tc, cursor, len, processed);
		return (error);
	} else if (tc->mode == HWT_MODE_CPU) {
		CPU_FOREACH_ISSET(cpu_id, &tc->cpu_map) {
			error = cs_process_chunk(tc, &dec[cpu_id], cursor, len,
			    processed);
			if (error)
				return (error);
		}
	} else {
		error = cs_process_chunk(tc, dec, cursor, len, processed);
		return (error);
	}

	return (0);
}

static int
hwt_coresight_init1(struct trace_context *tc, struct cs_decoder *dec)
{
	int cpu_id;
	int error;

	if (tc->raw) {
		/* No decoder needed, just a file for raw data. */
		tc->raw_f = fopen(tc->filename, "w");
		if (tc->raw_f == NULL) {
			printf("could not open file %s\n", tc->filename);
			return (ENXIO);
		}
	} else if (tc->mode == HWT_MODE_CPU) {
		CPU_FOREACH_ISSET(cpu_id, &tc->cpu_map) {
			error = hwt_coresight_init(tc, &dec[cpu_id], cpu_id);
			if (error)
				return (error);
		}
	} else {
		error = hwt_coresight_init(tc, dec, tc->thread_id);
		if (error)
			return (error);
	}

	return (0);
}

static void
catch_int(int sig_num __unused)
{

	printf("Decoder stopped\n");
	exit(0);
}

static int
hwt_coresight_process(struct trace_context *tc)
{
	size_t offs;
	size_t new_offs;
	int error;
	int t;
	struct cs_decoder *dec;
	uint32_t processed;
	size_t cursor;
	int len;
	size_t totals;
	int ncpu;

	xo_open_container("trace");
	xo_open_list("entries");

	signal(SIGINT, catch_int);

	ocsd_def_errlog_init(OCSD_ERR_SEV_INFO, 1);

	ncpu = hwt_ncpu();

	dec = malloc(sizeof(struct cs_decoder) * ncpu);

	error = hwt_coresight_init1(tc, dec);
	if (error)
		return (error);

	error = hwt_get_offs(tc, &offs);
	if (error) {
		printf("%s: cant get offset\n", __func__);
		return (-1);
	}


	printf("Decoder started. Press ctrl+c to stop.\n");

	cursor = 0;
	processed = 0;
	totals = 0;
	len = offs;

	cs_process_chunk1(tc, dec, cursor, len, &processed);
	cursor += processed;
	totals += processed;

	t = 0;

	while (1) {
		error = hwt_get_offs(tc, &new_offs);
		if (error)
			return (-1);

		if (new_offs == cursor) {
			/* No new entries in trace. */
			if (tc->terminate && t++ > 2)
				break;
			hwt_sleep(10);
		} else if (new_offs > cursor) {
			/* New entries in the trace buffer. */
			len = new_offs - cursor;
			cs_process_chunk1(tc, dec, cursor, len, &processed);
			cursor += processed;
			totals += processed;
			t = 0;

		} else if (new_offs < cursor) {
			/* New entries in the trace buffer. Buffer wrapped. */
			len = tc->bufsize - cursor;
			cs_process_chunk1(tc, dec, cursor, len, &processed);
			cursor += processed;
			totals += processed;

			cursor = 0;
			len = new_offs;
			cs_process_chunk1(tc, dec, cursor, len, &processed);
			cursor += processed;
			totals += processed;
			t = 0;
		}
	}

	printf("\nBytes processed: %ld\n", totals);

	xo_close_list("file");
	xo_close_container("wc");
	if (xo_finish() < 0)
		xo_err(EXIT_FAILURE, "stdout");

	return (0);
}

struct trace_dev_methods cs_methods = {
	.process = hwt_coresight_process,
	.set_config = hwt_coresight_set_config,
};
