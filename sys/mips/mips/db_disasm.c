/*	$OpenBSD: db_disasm.c,v 1.1 1998/03/16 09:03:24 pefo Exp $	*/
/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)kadb.c	8.1 (Berkeley) 6/10/93
 *	Id: db_disasm.c,v 1.1 1998/03/16 09:03:24 pefo Exp
 *	JNPR: db_disasm.c,v 1.1 2006/08/07 05:38:57 katta
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <vm/vm_param.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <sys/systm.h>

#include <machine/mips_opcode.h>
#include <machine/db_machdep.h>
#include <ddb/ddb.h>
#include <ddb/db_output.h>

static char *op_name[64] = {
/* 0 */ "spec", "bcond","j",	"jal",	"beq",	"bne",	"blez",	"bgtz",
/* 8 */ "addi", "addiu","slti",	"sltiu","andi",	"ori",	"xori",	"lui",
/*16 */ "cop0", "cop1",	"cop2",	"cop3", "beql",	"bnel",	"blezl","bgtzl",
/*24 */ "daddi","daddiu","ldl",	"ldr",	"op34",	"op35",	"op36",	"op37",
/*32 */ "lb",	"lh",	"lwl",	"lw",	"lbu",	"lhu",	"lwr",	"lwu",
/*40 */ "sb",	"sh",	"swl",	"sw",	"sdl",	"sdr",	"swr",	"cache",
/*48 */ "ll",	"lwc1",	"lwc2",	"lwc3", "lld",	"ldc1",	"ldc2",	"ld",
/*56 */ "sc",	"swc1",	"swc2",	"swc3", "scd",	"sdc1",	"sdc2",	"sd"
};

static char *spec_name[64] = {
/* 0 */ "sll",	"spec01","srl", "sra",	"sllv",	"spec05","srlv","srav",
/* 8 */ "jr",	"jalr",	"movz", "movn","syscall","break","spec16","sync",
/*16 */ "mfhi",	"mthi",	"mflo", "mtlo",	"dsllv","spec25","dsrlv","dsrav",
/*24 */ "mult",	"multu","div",	"divu",	"dmult","dmultu","ddiv","ddivu",
/*32 */ "add",	"addu",	"sub",	"subu",	"and",	"or",	"xor",	"nor",
/*40 */ "spec50","spec51","slt","sltu",	"dadd","daddu","dsub","dsubu",
/*48 */ "tge","tgeu","tlt","tltu","teq","spec65","tne","spec67",
/*56 */ "dsll","spec71","dsrl","dsra","dsll32","spec75","dsrl32","dsra32"
};

static char *bcond_name[32] = {
/* 0 */ "bltz",	"bgez",	"bltzl", "bgezl", "?", "?", "?", "?",
/* 8 */ "tgei",	"tgeiu", "tlti", "tltiu", "teqi", "?", "tnei", "?",
/*16 */ "bltzal", "bgezal", "bltzall", "bgezall", "?", "?", "?", "?",
/*24 */ "?", "?", "?", "?", "?", "?", "?", "synci",
};

static char *cop1_name[64] = {
/* 0 */ "fadd",	"fsub",	"fmpy",	"fdiv",	"fsqrt","fabs",	"fmov",	"fneg",
/* 8 */ "fop08","fop09","fop0a","fop0b","fop0c","fop0d","fop0e","fop0f",
/*16 */ "fop10","fop11","fop12","fop13","fop14","fop15","fop16","fop17",
/*24 */ "fop18","fop19","fop1a","fop1b","fop1c","fop1d","fop1e","fop1f",
/*32 */ "fcvts","fcvtd","fcvte","fop23","fcvtw","fop25","fop26","fop27",
/*40 */ "fop28","fop29","fop2a","fop2b","fop2c","fop2d","fop2e","fop2f",
/*48 */ "fcmp.f","fcmp.un","fcmp.eq","fcmp.ueq","fcmp.olt","fcmp.ult",
	"fcmp.ole","fcmp.ule",
/*56 */ "fcmp.sf","fcmp.ngle","fcmp.seq","fcmp.ngl","fcmp.lt","fcmp.nge",
	"fcmp.le","fcmp.ngt"
};

static char *fmt_name[16] = {
	"s",	"d",	"e",	"fmt3",
	"w",	"fmt5",	"fmt6",	"fmt7",
	"fmt8",	"fmt9",	"fmta",	"fmtb",
	"fmtc",	"fmtd",	"fmte",	"fmtf"
};

static char *reg_name[32] = {
	"zero",	"at",	"v0",	"v1",	"a0",	"a1",	"a2",	"a3",
#if defined(__mips_n32) || defined(__mips_n64)
	"a4",	"a5",	"a6",	"a7",	"t0",	"t1",	"t2",	"t3",
#else
	"t0",	"t1",	"t2",	"t3",	"t4",	"t5",	"t6",	"t7",
#endif
	"s0",	"s1",	"s2",	"s3",	"s4",	"s5",	"s6",	"s7",
	"t8",	"t9",	"k0",	"k1",	"gp",	"sp",	"s8",	"ra"
};

static char *c0_opname[64] = {
	"c0op00","tlbr",  "tlbwi", "c0op03","c0op04","c0op05","tlbwr", "c0op07",
	"tlbp",	"c0op11","c0op12","c0op13","c0op14","c0op15","c0op16","c0op17",
	"rfe",	"c0op21","c0op22","c0op23","c0op24","c0op25","c0op26","c0op27",
	"eret","c0op31","c0op32","c0op33","c0op34","c0op35","c0op36","c0op37",
	"c0op40","c0op41","c0op42","c0op43","c0op44","c0op45","c0op46","c0op47",
	"c0op50","c0op51","c0op52","c0op53","c0op54","c0op55","c0op56","c0op57",
	"c0op60","c0op61","c0op62","c0op63","c0op64","c0op65","c0op66","c0op67",
	"c0op70","c0op71","c0op72","c0op73","c0op74","c0op75","c0op77","c0op77",
};

static char *c0_reg[32] = {
	"index","random","tlblo0","tlblo1","context","tlbmask","wired","c0r7",
	"badvaddr","count","tlbhi","c0r11","sr","cause","epc",	"prid",
	"config","lladr","watchlo","watchhi","xcontext","c0r21","c0r22","c0r23",
	"c0r24","c0r25","ecc","cacheerr","taglo","taghi","errepc","c0r31"
};

#ifdef CPU_CHERI
static const char *cheri_cap_load_opname[8] = {
	"clbu", "clhu", "clwu", "cldu",
	"clb", "clh", "clw", "clld"
};
static const char *cheri_cap_store_opname[8] = {
	"csb", "csh", "csw", "csd",
	"csb", "csh", "csw", "cscd"
};
static const char *cheri_flow_control_opname[16] = {
	"invalid", "invalid", "invalid", "cunseal",
	"invalid", "ccall", "creturn", "cjalr",
	"cjr", "invalid", "invalid", "invalid",
	"ctoptr", "cgetoffset", "invalid", "invalid"
};

static const char *cheri_cap_modify_name[8] = {
	"candperm", "invalid", "invalid", "invalid",
	"invalid", "ccleartag", "invalid", "cfromptr"
};

enum CheriOperandType {
	COPT_UNKNOWN,	/* Unknown register kind (for undefined instrs) */
	COPT_GPR,	/* General-purpose integer register */
	COPT_CAP,	/* General-purpose capability register */
	COPT_OTHER,	/* Other register kind (e.g. special cap hwregs) */
	COPT_NONE,	/* Do not print another operand */
};

struct cheri_operand_info {
	const char* name;
	enum CheriOperandType op1_type;
	enum CheriOperandType op2_type;
	enum CheriOperandType op3_type;
};

static struct cheri_operand_info cheri_three_op_info[64] = {
	/* 0x00 */ {"cgetperm (old)", COPT_GPR, COPT_CAP },
	/* 0x01 */ {"cgettype (old)", COPT_GPR, COPT_CAP },
	/* 0x02 */ {"cgetbase (old)", COPT_GPR, COPT_CAP },
	/* 0x03 */ {"cgetlen (old)", COPT_GPR, COPT_CAP },
	/* 0x04 */ {"cgetcause (old)", COPT_GPR, COPT_NONE },
	/* 0x05 */ {"cgettag (old)", COPT_GPR, COPT_CAP },
	/* 0x06 */ {"cgetsealed (old)", COPT_GPR, COPT_CAP },
	/* 0x07 */ {"cgetpcc (old)", COPT_CAP, COPT_NONE },

	/* 0x08 */ {"csetbounds", COPT_CAP, COPT_CAP, COPT_GPR },
	/* 0x09 */ {"csetboundsexact", COPT_CAP, COPT_CAP, COPT_GPR },
	/* 0x0a */ {"csub", COPT_GPR, COPT_CAP, COPT_CAP },
	/* 0x0b */ {"cseal", COPT_CAP, COPT_CAP, COPT_CAP },
	/* 0x0c */ {"cunseal", COPT_CAP, COPT_CAP, COPT_CAP },
	/* 0x0d */ {"candperm", COPT_CAP, COPT_CAP, COPT_GPR },
	/* 0x0e */ {"invalid", COPT_UNKNOWN, COPT_UNKNOWN, COPT_UNKNOWN },
	/* 0x0f */ {"csetoffset", COPT_CAP, COPT_CAP, COPT_GPR },

	/* 0x10 */ {"invalid", COPT_UNKNOWN, COPT_UNKNOWN, COPT_UNKNOWN },
	/* 0x11 */ {"cincoffset", COPT_CAP, COPT_CAP, COPT_GPR },
	/* 0x12 */ {"ctoptr", COPT_GPR, COPT_CAP, COPT_CAP },
	/* 0x13 */ {"cfromptr", COPT_CAP, COPT_CAP, COPT_GPR },
	/* 0x14 */ {"ceq", COPT_GPR, COPT_CAP, COPT_GPR },
	/* 0x15 */ {"cne", COPT_GPR, COPT_CAP, COPT_GPR },
	/* 0x16 */ {"clt", COPT_GPR, COPT_CAP, COPT_GPR },
	/* 0x17 */ {"cle", COPT_GPR, COPT_CAP, COPT_GPR },

	/* 0x18 */ {"cltu", COPT_GPR, COPT_CAP, COPT_GPR },
	/* 0x19 */ {"cleu", COPT_GPR, COPT_CAP, COPT_GPR },
	/* 0x1a */ {"cexeq", COPT_GPR, COPT_CAP, COPT_GPR },
	/* 0x1b */ {"cmovn", COPT_CAP, COPT_CAP, COPT_GPR },
	/* 0x1c */ {"cmovz", COPT_CAP, COPT_CAP, COPT_GPR },
	/* 0x00 */ {"cbuildcap", COPT_CAP, COPT_CAP, COPT_CAP },
	/* 0x00 */ {"ccopytype", COPT_CAP, COPT_CAP, COPT_CAP },
	/* 0x1f */ {"ccseal", COPT_CAP, COPT_CAP, COPT_CAP },

	/* 0x20 */ {"ctestsubset", COPT_GPR, COPT_CAP, COPT_CAP },
	/* 0x21 */ {"cnexeq", COPT_GPR, COPT_CAP, COPT_CAP },
	/* 0x22 */ {"csetaddr", COPT_CAP, COPT_CAP, COPT_GPR },
	/* 0x23 */ {"cgetandaddr", COPT_GPR, COPT_CAP, COPT_GPR },
	/* 0x24 */ {"candddr", COPT_CAP, COPT_CAP, COPT_GPR },
};

static struct cheri_operand_info cheri_two_op_info[32] = {
	/* 0x00 */ { "cgetperm", COPT_GPR, COPT_CAP },
	/* 0x01 */ { "cgettype", COPT_GPR, COPT_CAP },
	/* 0x02 */ { "cgetbase", COPT_GPR, COPT_CAP },
	/* 0x03 */ { "cgetlen", COPT_GPR, COPT_CAP },
	/* 0x04 */ { "cgettag", COPT_GPR, COPT_CAP },
	/* 0x05 */ { "cgetsealed", COPT_GPR, COPT_CAP },
	/* 0x06 */ { "cgetoffset", COPT_GPR, COPT_CAP },
	/* 0x07 */ { "cgetpccsetoffset", COPT_CAP, COPT_GPR },

	/* 0x08 */ { "ccheckperm", COPT_CAP, COPT_GPR },
	/* 0x09 */ { "cchecktype", COPT_CAP, COPT_GPR },
	/* 0x0a */ { "cmove", COPT_CAP, COPT_CAP },
	/* 0x0b */ { "ccleartag", COPT_CAP, COPT_CAP },
	/* 0x0c */ { "cjalr", COPT_CAP, COPT_CAP },
	/* 0x0d */ { "creadhwr", COPT_CAP, COPT_OTHER },
	/* 0x0e */ { "cwritehwr", COPT_CAP, COPT_OTHER },
	/* 0x0f */ { "cgetaddr", COPT_GPR, COPT_CAP },
};

static struct cheri_operand_info cheri_one_op_info[32] = {
	/* 0x00 */ { "cgetpcc", COPT_CAP },
	/* 0x01 */ { "cgetcause", COPT_GPR },
	/* 0x02 */ { "csetcause", COPT_GPR },
	/* 0x03 */ { "cjr", COPT_CAP },
	/* 0x04 */ { "cgetcid", COPT_GPR },
	/* 0x05 */ { "csetcid", COPT_GPR },
};

static const char *c2_reg[32] = {
	"ddc/cnull", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9",
	"c10", "c11", "c12", "c13", "c14", "c15", "c16", "c17", "c18", "c19",
	"c20", "c21", "c22", "c23", "c24", "c25", "idc/c26", "kr1c/c27",
	"kr2c/c28", "kcc/c29", "kdc/c30", "epcc/c31"
};

static const char *unknown_reg_names[32] = {
	"$0", "$1", "$2", "$3", "$4", "$5", "$6", "$7",
	"$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15",
	"$16", "$17", "$18", "$19", "$20", "$21", "$22", "$23",
	"$24", "$25", "$26", "$27", "$28", "$29", "$30", "$31"
};

static const char*
cheri_operand_to_str(enum CheriOperandType type, unsigned regno)
{
	KASSERT(regno <= 31,
	    ("invalid regno %d, corrupted disasm state?", regno));
	switch (type) {
	case COPT_GPR:
		return (reg_name[regno]);
	case COPT_CAP:
		return (c2_reg[regno]);
	case COPT_NONE:
		return ("(no-operand)");
	default:
		return (unknown_reg_names[regno]);
	}
}

#endif /* CPU_CHERI */

static int md_printins(int ins, int mdbdot);

db_addr_t
db_disasm(db_addr_t loc, bool altfmt)

{
	int ins;

	if (vtophys((vm_offset_t)loc)) {
		db_read_bytes((vm_offset_t)loc, (size_t)sizeof(int),
		    (char *)&ins);
		md_printins(ins, loc);
	}

	return (loc + sizeof(int));
}


/* ARGSUSED */
static int
md_printins(int ins, int mdbdot)
{
	InstFmt i;
	int delay = 0;

	i.word = ins;

	switch (i.JType.op) {
	case OP_SPECIAL:
		if (i.word == 0) {
			db_printf("nop");
			break;
		}
		if (i.RType.func == OP_ADDU && i.RType.rt == 0) {
			db_printf("move\t%s,%s",
			    reg_name[i.RType.rd], reg_name[i.RType.rs]);
			break;
		}
		db_printf("%s", spec_name[i.RType.func]);
		switch (i.RType.func) {
		case OP_SLL:
		case OP_SRL:
		case OP_SRA:
		case OP_DSLL:
		case OP_DSRL:
		case OP_DSRA:
		case OP_DSLL32:
		case OP_DSRL32:
		case OP_DSRA32:
			db_printf("\t%s,%s,%d", reg_name[i.RType.rd],
			    reg_name[i.RType.rt], i.RType.shamt);
			break;

		case OP_SLLV:
		case OP_SRLV:
		case OP_SRAV:
		case OP_DSLLV:
		case OP_DSRLV:
		case OP_DSRAV:
			db_printf("\t%s,%s,%s", reg_name[i.RType.rd],
			    reg_name[i.RType.rt], reg_name[i.RType.rs]);
			break;

		case OP_MFHI:
		case OP_MFLO:
			db_printf("\t%s", reg_name[i.RType.rd]);
			break;

		case OP_JR:
		case OP_JALR:
			delay = 1;
			/* FALLTHROUGH */
		case OP_MTLO:
		case OP_MTHI:
			db_printf("\t%s", reg_name[i.RType.rs]);
			break;

		case OP_MULT:
		case OP_MULTU:
		case OP_DMULT:
		case OP_DMULTU:
		case OP_DIV:
		case OP_DIVU:
		case OP_DDIV:
		case OP_DDIVU:
			db_printf("\t%s,%s",
			    reg_name[i.RType.rs], reg_name[i.RType.rt]);
			break;

		case OP_SYSCALL:
		case OP_SYNC:
			break;

		case OP_BREAK:
			db_printf("\t%d", (i.RType.rs << 5) | i.RType.rt);
			break;

		default:
			db_printf("\t%s,%s,%s", reg_name[i.RType.rd],
			    reg_name[i.RType.rs], reg_name[i.RType.rt]);
		}
		break;

	case OP_BCOND:
		db_printf("%s\t%s,", bcond_name[i.IType.rt],
		    reg_name[i.IType.rs]);
		goto pr_displ;

	case OP_BLEZ:
	case OP_BLEZL:
	case OP_BGTZ:
	case OP_BGTZL:
		db_printf("%s\t%s,", op_name[i.IType.op],
		    reg_name[i.IType.rs]);
		goto pr_displ;

	case OP_BEQ:
	case OP_BEQL:
		if (i.IType.rs == 0 && i.IType.rt == 0) {
			db_printf("b\t");
			goto pr_displ;
		}
		/* FALLTHROUGH */
	case OP_BNE:
	case OP_BNEL:
		db_printf("%s\t%s,%s,", op_name[i.IType.op],
		    reg_name[i.IType.rs], reg_name[i.IType.rt]);
	pr_displ:
		delay = 1;
		db_printf("0x%08x", mdbdot + 4 + ((short)i.IType.imm << 2));
		break;

#ifdef CPU_CHERI
	case OP_JALX:
		db_printf("clcbi\t%s, %d(%s)", c2_reg[i.IType.rs],
			(short)i.IType.imm * 16, c2_reg[i.IType.rt]);
		break;
	case OP_COP2: {
		int ops = -1;
		const char *opcode = NULL;
		const char *operands[3] = { 0 };
		struct cheri_operand_info* op_info = NULL;
		switch (i.CType.fmt) {
		case 0:
			if (i.CType.func != 0x3f) {
				/* Three operand instruction */
				ops = 3;
				op_info = &cheri_three_op_info[i.CType.func];
			} else if (i.CType.r3 != 0x1f) {
				/* Two operands instruction */
				ops = 2;
				op_info = &cheri_two_op_info[i.CType.r3];
			} else {
				/* One operand instruction */
				ops = 1;
				op_info = &cheri_one_op_info[i.CType.r2];
			}
			opcode = op_info->name;
			if (!opcode)
				opcode = "invalid";

			if (ops >= 3)
				operands[2] = cheri_operand_to_str(
				    op_info->op3_type, i.CType.r3);
			if (ops >= 2)
				operands[1] = cheri_operand_to_str(
				    op_info->op2_type, i.CType.r2);
			if (ops >= 1)
				operands[0] = cheri_operand_to_str(
				    op_info->op1_type, i.CType.r1);
			break;
		case 3:
			ops = 3;
			opcode = cheri_flow_control_opname[i.CTypeOld.fmt];
			operands[0] = c2_reg[i.CType.r1];
			operands[1] = c2_reg[i.CType.r2];
			operands[2] = c2_reg[i.CType.r3];
			break;
		case 4:
			opcode = cheri_cap_modify_name[i.CTypeOld.fmt2];
			if (i.CTypeOld.fmt2 == 5) {
				ops = 0;
			} else if (i.CTypeOld.fmt2 == 7) {
				ops = 3;
				operands[0] = c2_reg[i.CTypeOld.r1];
				operands[1] = c2_reg[i.CTypeOld.r2];
				operands[2] = reg_name[i.CTypeOld.r3];
			} else {
				ops = 3;
				operands[0] = reg_name[i.CTypeOld.r1];
				operands[1] = c2_reg[i.CTypeOld.r2];
			}
			break;
		case 5:
			/* CCall (TODO: disassemble the selector) */
			ops = 2;
			opcode = cheri_flow_control_opname[i.CTypeOld.fmt];
			operands[0] = c2_reg[i.CTypeOld.r1];
			operands[1] = c2_reg[i.CTypeOld.r2];
			break;
		case 6:
			ops = 0;
			opcode = cheri_flow_control_opname[i.CTypeOld.fmt];
			break;
		case 7:
		case 8:
			ops = 2;
			opcode = cheri_flow_control_opname[i.CTypeOld.fmt];
			operands[0] = c2_reg[i.CTypeOld.r2];
			operands[1] = reg_name[i.CTypeOld.r3];
			break;
		case 0x9:
			db_printf("cbtu\t%s,", c2_reg[i.BC2FType.cd]);
			goto pr_displ;
		case 0xa:
			db_printf("cbts\t%s,", c2_reg[i.BC2FType.cd]);
			goto pr_displ;
		case 0xd:
			ops = 2;
			opcode = cheri_flow_control_opname[i.CTypeOld.fmt];
			operands[0] = reg_name[i.CTypeOld.r1];
			operands[1] = c2_reg[i.CTypeOld.r2];
			break;
		case 0x11:
			db_printf("cbez\t%s,", c2_reg[i.BC2FType.cd]);
			goto pr_displ;
		case 0x12:
			db_printf("cbnz\t%s,", c2_reg[i.BC2FType.cd]);
			goto pr_displ;
		case 0x13: {
			/* CIncOffset with 11 bit signed immediate */
			int immediate = (i.CType.r3 << 6) | i.CType.func;
			if (immediate > 1024)
				immediate = -immediate;
			db_printf("cincoffset\t%s, %s, %d", c2_reg[i.CType.r1],
			    c2_reg[i.CType.r2], immediate);
			goto cp2_disas_done;
		}
		case 0x14: {
			/* CSetBounds with 11 bit unsigned immediate */
			int immediate = (i.CType.r3 << 6) | i.CType.func;
			db_printf("csetbounds\t%s, %s, %d", c2_reg[i.CType.r1],
			    c2_reg[i.CType.r2], immediate);
			goto cp2_disas_done;
		}
		default:
			ops = 0;
			opcode = "<unknown inst>";
			break;
		}

		switch (ops) {
		case 0:
			db_printf("%s", opcode);
			break;
		case 1:
			db_printf("%s\t%s", opcode, operands[0]);
			break;
		case 2:
			db_printf("%s\t%s,%s", opcode, operands[0], operands[1]);
			break;
		case 3:
			db_printf("%s\t%s,%s,%s", opcode, operands[0], operands[1],
					operands[2]);
			break;
		default:
			db_printf("unknown COP2 opcode (fmt %d, func %d)", i.CType.fmt, i.CType.func);
			break;
		}
cp2_disas_done:
		(void)0;
	}
		break;
	case OP_LWC2:
	case OP_SWC2: {
		const char *opcode = i.JType.op == OP_LWC2 ?
			cheri_cap_load_opname[i.CMType.fmt] :
			cheri_cap_store_opname[i.CMType.fmt];
		db_printf("%s\t%s,%s,%d(%s)", opcode, reg_name[i.CMType.rd],
				reg_name[i.CMType.rt], i.CMType.offset, c2_reg[i.CMType.cb]);
		break;
	}
	case OP_LDC2:
	case OP_SDC2: {
		const char *opcode = i.JType.op == OP_LDC2 ? "clc" : "csc";
		db_printf("%s\t%s,%s,%d(%s)", opcode, c2_reg[i.CCMType.cs],
		    reg_name[i.CCMType.rt], i.CCMType.offset * 16,
		    c2_reg[i.CCMType.cb]);
		break;
	}
#endif /* CPU_CHERI */

	case OP_COP0:
		switch (i.RType.rs) {
		case OP_BCx:
		case OP_BCy:
			db_printf("bc0%c\t",
			    "ft"[i.RType.rt & COPz_BC_TF_MASK]);
			goto pr_displ;

		case OP_MT:
			db_printf("mtc0\t%s,%s",
			    reg_name[i.RType.rt], c0_reg[i.RType.rd]);
			break;

		case OP_DMT:
			db_printf("dmtc0\t%s,%s",
			    reg_name[i.RType.rt], c0_reg[i.RType.rd]);
			break;

		case OP_MF:
			db_printf("mfc0\t%s,%s",
			    reg_name[i.RType.rt], c0_reg[i.RType.rd]);
			break;

		case OP_DMF:
			db_printf("dmfc0\t%s,%s",
			    reg_name[i.RType.rt], c0_reg[i.RType.rd]);
			break;

		default:
			db_printf("%s", c0_opname[i.FRType.func]);
		}
		break;

	case OP_COP1:
		switch (i.RType.rs) {
		case OP_BCx:
		case OP_BCy:
			db_printf("bc1%c\t",
			    "ft"[i.RType.rt & COPz_BC_TF_MASK]);
			goto pr_displ;

		case OP_MT:
			db_printf("mtc1\t%s,f%d",
			    reg_name[i.RType.rt], i.RType.rd);
			break;

		case OP_MF:
			db_printf("mfc1\t%s,f%d",
			    reg_name[i.RType.rt], i.RType.rd);
			break;

		case OP_CT:
			db_printf("ctc1\t%s,f%d",
			    reg_name[i.RType.rt], i.RType.rd);
			break;

		case OP_CF:
			db_printf("cfc1\t%s,f%d",
			    reg_name[i.RType.rt], i.RType.rd);
			break;

		default:
			db_printf("%s.%s\tf%d,f%d,f%d",
			    cop1_name[i.FRType.func], fmt_name[i.FRType.fmt],
			    i.FRType.fd, i.FRType.fs, i.FRType.ft);
		}
		break;

	case OP_J:
	case OP_JAL:
		db_printf("%s\t", op_name[i.JType.op]);
		db_printf("0x%8x",(mdbdot & 0xF0000000) | (i.JType.target << 2));
		delay = 1;
		break;

	case OP_LWC1:
	case OP_SWC1:
		db_printf("%s\tf%d,", op_name[i.IType.op], i.IType.rt);
		goto loadstore;

	case OP_LB:
	case OP_LH:
	case OP_LW:
	case OP_LD:
	case OP_LBU:
	case OP_LHU:
	case OP_LWU:
	case OP_SB:
	case OP_SH:
	case OP_SW:
	case OP_SD:
		db_printf("%s\t%s,", op_name[i.IType.op],
		    reg_name[i.IType.rt]);
	loadstore:
		db_printf("%d(%s)", (short)i.IType.imm, reg_name[i.IType.rs]);
		break;

	case OP_ORI:
	case OP_XORI:
		if (i.IType.rs == 0) {
			db_printf("li\t%s,0x%x",
			    reg_name[i.IType.rt], i.IType.imm);
			break;
		}
		/* FALLTHROUGH */
	case OP_ANDI:
		db_printf("%s\t%s,%s,0x%x", op_name[i.IType.op],
		    reg_name[i.IType.rt], reg_name[i.IType.rs], i.IType.imm);
		break;

	case OP_LUI:
		db_printf("%s\t%s,0x%x", op_name[i.IType.op],
		    reg_name[i.IType.rt], i.IType.imm);
		break;

	case OP_ADDI:
	case OP_DADDI:
	case OP_ADDIU:
	case OP_DADDIU:
		if (i.IType.rs == 0) {
			db_printf("li\t%s,%d", reg_name[i.IType.rt],
			    (short)i.IType.imm);
			break;
		}
		/* FALLTHROUGH */
	default:
		db_printf("%s\t%s,%s,%d", op_name[i.IType.op],
		    reg_name[i.IType.rt], reg_name[i.IType.rs],
		    (short)i.IType.imm);
	}
	db_printf("\n");
	return (delay);
}
