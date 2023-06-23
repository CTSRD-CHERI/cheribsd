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
#include "hwtvar.h"
#include "hwt_coresight.h"

#include "libpmcstat_stubs.h"
#include <libpmcstat.h>

#define	PMCTRACE_CS_DEBUG
#undef	PMCTRACE_CS_DEBUG

#ifdef	PMCTRACE_CS_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static dcd_tree_handle_t dcdtree_handle;
static int cs_flags = 0;
#define	FLAG_FORMAT			(1 << 0)
#define	FLAG_FRAME_RAW_UNPACKED		(1 << 1)
#define	FLAG_FRAME_RAW_PACKED		(1 << 2)
#define	FLAG_CALLBACK_MEM_ACC		(1 << 3)

#define	PACKET_STR_LEN	1024
static char packet_str[PACKET_STR_LEN];

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

#if 0
static uint32_t
cs_decoder__mem_access(const void *context __unused,
    const ocsd_vaddr_t address __unused,
    const ocsd_mem_space_acc_t mem_space __unused,
    const uint32_t req_size __unused, uint8_t *buffer __unused)
{

	/* TODO */

	return (0);
}
#endif

static ocsd_err_t
create_test_memory_acc(dcd_tree_handle_t handle, struct trace_context *tc)
{
	ocsd_vaddr_t address;
	uint8_t *p_mem_buffer;
	uint32_t mem_length;
	int ret;

	dprintf("%s\n", __func__);

#if 0
	if (cs_flags & FLAG_CALLBACK_MEM_ACC)
		ret = ocsd_dt_add_callback_mem_acc(handle, base + start,
			base + end - 1, OCSD_MEM_SPACE_ANY,
			cs_decoder__mem_access, NULL);
	else
#endif
	{
		address = (ocsd_vaddr_t)tc->base;

		uint64_t *t;
		t = (uint64_t *)tc->base;
		printf("%lx %lx %lx %lx\n", t[0], t[1], t[2], t[3]);

		p_mem_buffer = (uint8_t *)tc->base;
		mem_length = tc->bufsize;

		ret = ocsd_dt_add_buffer_mem_acc(handle, address,
		    OCSD_MEM_SPACE_ANY, p_mem_buffer, mem_length);
	}

	if (ret != OCSD_OK)
		printf("%s: can't create memory accessor: ret %d\n",
		    __func__, ret);

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

	printf("%s: CSID %d\n", __func__, CSID);

	if (cs_flags & FLAG_FORMAT) {
		ret = ocsd_dt_attach_packet_callback(handle, CSID,
		    OCSD_C_API_CB_PKT_MON, packet_monitor, p_context);
		if (ret != OCSD_OK)
			return (-1);
	}

	/* attach a memory accessor */
	ret = create_test_memory_acc(handle, tc);
	if (ret != OCSD_OK)
		ocsd_dt_remove_decoder(handle, CSID);

	return (ret);
}

static ocsd_err_t
create_decoder_etmv4(dcd_tree_handle_t dcd_tree_h, struct trace_context *tc)
{
	ocsd_etmv4_cfg trace_config;
	ocsd_err_t ret;

	trace_config.arch_ver = ARCH_V8;
	trace_config.core_prof = profile_CortexA;

	trace_config.reg_configr = 0x00001fc6;
	trace_config.reg_configr = 0x000000C1;
	trace_config.reg_traceidr = 0x00000001;	/* Trace ID */

	trace_config.reg_idr0   = 0x28000ea1;
	trace_config.reg_idr1   = 0x4100f424;
	trace_config.reg_idr2   = 0x20001088;
	trace_config.reg_idr8   = 0x0;
	trace_config.reg_idr9   = 0x0;
	trace_config.reg_idr10  = 0x0;
	trace_config.reg_idr11  = 0x0;
	trace_config.reg_idr12  = 0x0;
	trace_config.reg_idr13  = 0x0;

	/* Instruction decoder. */
	ret = create_generic_decoder(dcd_tree_h, OCSD_BUILTIN_DCD_ETMV4I,
	    (void *)&trace_config, 0, tc);

	return (ret);
}

static int
cs_process_chunk(struct trace_context *tc, size_t start, size_t end)
{
	uint32_t bytes_done;
	uint8_t *p_block;
	uint32_t bytes_this_time;
	int block_index;
	size_t block_size;
	int dp_ret;
	int ret;

	dprintf("%s: tc->base %#p\n", __func__, tc->base);

	bytes_this_time = 0;
	block_index = start;
	bytes_done = 0;
	block_size = end - start;
	p_block = (uint8_t *)((uintptr_t)tc->base + start);

	ret = OCSD_OK;
	dp_ret = OCSD_RESP_CONT;

	while (bytes_done < (uint32_t)block_size && (ret == OCSD_OK)) {

		if (OCSD_DATA_RESP_IS_CONT(dp_ret)) {
			dprintf("process data, block_size %ld, bytes_done %d\n",
			    block_size, bytes_done);
			dp_ret = ocsd_dt_process_data(dcdtree_handle,
			    OCSD_OP_DATA,
			    block_index + bytes_done,
			    block_size - bytes_done,
			    ((uint8_t *)p_block) + bytes_done,
			    &bytes_this_time);
			bytes_done += bytes_this_time;
			dprintf("BYTES DONE %d\n", bytes_done);
			if (OCSD_DATA_RESP_IS_WAIT(dp_ret)) {
printf("wait");
				exit(12);
			}

		} else if (OCSD_DATA_RESP_IS_WAIT(dp_ret)) {
printf("WAIT");
exit(5);
			dp_ret = ocsd_dt_process_data(dcdtree_handle,
			    OCSD_OP_FLUSH, 0, 0, NULL, NULL);
		} else {
printf("FATAL");
exit(6);
			ret = OCSD_ERR_DATA_DECODE_FATAL;
		}
	}

	//ocsd_dt_process_data(dcdtree_handle, OCSD_OP_EOT, 0, 0, NULL, NULL);

	return (0);
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


static ocsd_datapath_resp_t
gen_trace_elem_print_lookup(const void *p_context,
    const ocsd_trc_index_t index_sop __unused,
    const uint8_t trc_chan_id __unused,
    const ocsd_generic_trace_elem *elem)
{
	const struct trace_context *tc;
	struct pmcstat_image *image;
	ocsd_datapath_resp_t resp;
	struct pmcstat_symbol *sym;
	unsigned long offset;
	uint64_t newpc;
	uint64_t ip;

	tc = (const struct trace_context *)p_context;

	resp = OCSD_RESP_CONT;

#if 0
	dprintf("%s: Idx:%d ELEM TYPE %d, st_addr %lx, en_addr %lx\n",
	    __func__, index_sop, elem->elem_type,
	    elem->st_addr, elem->en_addr);
#endif

#if 0
	if (elem->st_addr == -1)
		return (resp);
#endif

	if (elem->st_addr == 0)
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
		printf("Unknown packet.\n");
		return (resp);
	case OCSD_GEN_TRC_ELEM_NO_SYNC:
		printf("No sync.\n");
		return (resp);
	case OCSD_GEN_TRC_ELEM_TRACE_ON:
		printf("Trace on.\n");
		return (resp);
	case OCSD_GEN_TRC_ELEM_EO_TRACE:
		printf("End of Trace.\n");
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
		printf("Exception #%d (%s)\n", elem->exception_number,
		    ARMv8Excep[elem->exception_number]);
		return (resp);
	case OCSD_GEN_TRC_ELEM_EXCEPTION_RET:
		printf("Exception RET to %lx\n", elem->st_addr);
		return (resp);
	case OCSD_GEN_TRC_ELEM_TIMESTAMP:
		printf("Timestamp: %lx\n", elem->timestamp);
		return (resp);
	case OCSD_GEN_TRC_ELEM_CYCLE_COUNT:
		printf("Cycle count: %d\n", elem->cycle_count);
		return (resp);
	case OCSD_GEN_TRC_ELEM_EVENT:
	case OCSD_GEN_TRC_ELEM_SWTRACE:
	case OCSD_GEN_TRC_ELEM_SYNC_MARKER:
	case OCSD_GEN_TRC_ELEM_MEMTRANS:
	case OCSD_GEN_TRC_ELEM_INSTRUMENTATION:
	case OCSD_GEN_TRC_ELEM_CUSTOM:
		return (resp);
	};

#if 0
	char ts[100];

	if (elem->timestamp != 0)
		sprintf(ts, "ts %ld", elem->timestamp);
	else
		sprintf(ts, "                  ");
#endif

	if (sym) {
		offset = newpc - (sym->ps_start + image->pi_vaddr);

		printf("pc 0x%08lx (%lx)\t%12s\t%s+0x%lx\n", //elem->elem_type,
		    ip, newpc,
		    pmcstat_string_unintern(image->pi_name),
		    pmcstat_string_unintern(sym->ps_name), offset);
	} else
		if (image)
			printf("pc 0x%08lx (%lx)\t%12s\n", //elem->elem_type,
			    ip, newpc,
			    pmcstat_string_unintern(image->pi_name));
		else {
			/* image not found. */
		}

	return (resp);
}

int
hwt_coresight_init(struct trace_context *tc)
{
	int error;

	ocsd_def_errlog_init(OCSD_ERR_SEV_INFO, 1);

	dcdtree_handle = ocsd_create_dcd_tree(OCSD_TRC_SRC_FRAME_FORMATTED,
	    OCSD_DFRMTR_FRAME_MEM_ALIGN);
	if (dcdtree_handle == C_API_INVALID_TREE_HANDLE) {
		printf("can't find dcd tree\n");
		return (-1);
	}

	//cs_flags |= FLAG_FORMAT;
	//cs_flags |= FLAG_FRAME_RAW_UNPACKED;
	//cs_flags |= FLAG_FRAME_RAW_PACKED;

	error = create_decoder_etmv4(dcdtree_handle, tc);
	if (error != OCSD_OK) {
		printf("can't create decoder: tc->base %#p\n", tc->base);
		return (-2);
	}

#ifdef PMCTRACE_CS_DEBUG
	ocsd_tl_log_mapped_mem_ranges(dcdtree_handle);
#endif

	if (cs_flags & FLAG_FORMAT)
		ocsd_dt_set_gen_elem_printer(dcdtree_handle);
	else
		ocsd_dt_set_gen_elem_outfn(dcdtree_handle,
		    gen_trace_elem_print_lookup, tc);

	attach_raw_printers(dcdtree_handle);

	return (0);
}

int
hwt_coresight_process(struct trace_context *tc)
{
	size_t start;
	size_t end;
	size_t offs;
	int error;

	/* Coresight data is always on CPU0 due to funnelling by HW. */

	hwt_coresight_init(tc);

	error = hwt_get_offs(tc, &offs);
printf("OFFS %ld\n", offs);
	if (error)
		return (-1);

	printf("data to process %ld\n", offs);

	start = 0;
	end = offs;

	cs_process_chunk(tc, start, end);

	int t;

	t = 0;

	while (1) {
		hwt_sleep();

		if (tc->terminate && t++ > 2)
			break;

		error = hwt_get_offs(tc, &offs);
printf("OFFS %ld, err %d\n", offs, error);
		if (error)
			return (-1);

		if (offs == end) {
			/* No new entries in trace. */
			hwt_sleep();
			continue;
		}

		if (offs > end) {
			/* New entries in the trace buffer. */
			start = end;
			end = offs;
			cs_process_chunk(tc, start, end);
			hwt_sleep();
			continue;
		}

		if (offs < end) {
			/* New entries in the trace buffer. Buffer wrapped. */
			start = end;
			end = tc->bufsize;
			cs_process_chunk(tc, start, end);

			start = 0;
			end = offs;
			cs_process_chunk(tc, start, end);

			hwt_sleep();
		}
	}

	return (0);
}
