/*-
 * Copyright (c) 2011-2015 Robert N. M. Watson
 * Copyright (c) 2017-2018 Alex Richardson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
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

/*
 * Linker definition for a relocatable sandbox binary.
 *
 * The bottom 0x8000 bytes is owned by the sandbox runtime, but will normally
 * start with a guard page at 0x0, followed by metadata at 0x1000.  Code
 * linkage begins with a series of entry vectors, followed by the proper body
 * of the code segment.  Each vector has room for 128 instructions.
 *
 * Data is page-aligned above code, unlike with conventional linker scripts,
 * to ensure that we need to map code or data into only one of code and data
 * capabilities, which can have suitable restricted permissions.
 */
__vector_base__ = 0x8000;
__vector_size__ = 0x200;

__rtld_vector_addr__ = __vector_base__ + __vector_size__ * 0;
__invoke_vector_addr__ = __vector_base__ + __vector_size__ * 1;
PROVIDE_HIDDEN(__reserved0_vector__ = __vector_base__ + __vector_size__ * 2);
PROVIDE_HIDDEN(__reserved1_vector__ = __vector_base__ + __vector_size__ * 3);

__vector_end_addr__ = __vector_base__ + __vector_size__ * 4;

CAP_ALIGN = 0x20;
PAGE_ALIGN = 0x1000;

/*
 * Unlike BFD, LLD doesn't implicitly add any name referenced by an input
 * section description as an input file: When we were linkingi with bfd the
 * crt_rtld.o and crt_invoke.o files were implicitly pulled in because they
 * are mentioned in the following output section descriptions. With LLD we need
 * to explicitly use INPUT()
 */
INPUT(crt_rtld.o crt_invoke.o)
INPUT(crtbeginC.o crtendC.o)
/* Currently needed to process __cap_relocs and .init_array in sandboxes: */
INPUT(Ccrt1.o)

ENTRY(__rtld_vector)
/* Not supported by LLD: STARTUP(crt_rtld.o) */

SECTIONS
{
	. = __rtld_vector_addr__;
	/* XXXAR: we can't call these sections .text.rtld_vector anymore
	 * because LLD will merge any sections starting with .text., .data., etc.
	 * I believe this is a bug in LLD but for now work around it by using
	 * a different name for the section. Using a valid C identifier has the
	 * added benefit that we get a __start_sec and __stop_sec symbol from
	 * the linker that we can use to verify that the output was correct/
	 */
	/*
	 * Adding the . after the section name forces the output section
	 * to be placed at the address of the current location counter:
	 * https://sourceware.org/binutils/docs/ld/Output-Section-Address.html
	 *
	 * Specifying the address again rather than . ensures that . doesn't
	 * change due to orphan sections being added in unwanted places. If LLD
	 * decides to put an orphan section where our vectors belong, it will
	 * instead give an error about overlapping sections, rather than
	 * shifting a vector entry.
	 */
	rtld_vector_text __rtld_vector_addr__ : {
		KEEP(*crt_rtld.o(.text *vector_text))
	}
	. = __invoke_vector_addr__;
	invoke_vector_text __invoke_vector_addr__ : {
		KEEP(*crt_invoke.o(.text *vector_text))
	}
	. = __vector_end_addr__;
	.init : {
		KEEP (*(.init))
	} = 0
	.text ALIGN(CAP_ALIGN): {
		KEEP(*(.text*))
	}
	.fini ALIGN(CAP_ALIGN): {
		KEEP (*(.fini))
	} = 0
	.note.tag : {
		*(.note.tag)
	}
	.MIPS.options ALIGN(PAGE_ALIGN): {
		*(.MIPS.options)
	}
	.MIPS.abiflags ALIGN(PAGE_ALIGN): {
		*(.MIPS.abiflags)
	}
	.rodata ALIGN(CAP_ALIGN) : {
		*(.rodata)
	}
	__cap_relocs : {
		KEEP(*(__cap_relocs))
	}
	/*
	 * Memory to be mapped into the data segment.  For compiler-generated
	 * content, it would be much preferable to map into the code segment
	 * and use $pcc-relative loads, but we are not yet there.
	 */
	.ctors ALIGN(CAP_ALIGN) : {
		KEEP (crtbeginC.o(.ctors))
		KEEP (*(EXCLUDE_FILE (*crtendC.o) .ctors))
		KEEP (*(SORT(.ctors.*)))
		KEEP (crtendC.o(.ctors))
	}
	.dtors ALIGN(CAP_ALIGN) : {
		KEEP (crtbeginC.o(.dtors))
		KEEP (*(EXCLUDE_FILE (*crtendC.o) .dtors))
		KEEP (*(SORT(.dtors.*)))
		KEEP (crtendC.o(.dtors))
	}
	.preinit_array ALIGN(CAP_ALIGN) : {
		PROVIDE_HIDDEN (__preinit_array_start = .);
		KEEP (*(.preinit_array))
		PROVIDE_HIDDEN (__preinit_array_end = .);
	}
	.init_array ALIGN(CAP_ALIGN) : {
		PROVIDE_HIDDEN (__init_array_start = .);
		KEEP (*(SORT(.init_array.*)))
		KEEP (*(.init_array))
		PROVIDE_HIDDEN (__init_array_end = .);
	}
	.fini_array ALIGN(CAP_ALIGN) : {
		PROVIDE_HIDDEN (__fini_array_start = .);
		KEEP (*(.fini_array))
		KEEP (*(SORT(.fini_array.*)))
		PROVIDE_HIDDEN (__fini_array_end = .);
	}
	.data ALIGN(CAP_ALIGN): {
		*(.data)
	}
	.got ALIGN(CAP_ALIGN): {
		*(.got.plt)
		*(.got)
	}
	.bss ALIGN(CAP_ALIGN): {
		*(.bss)
	}

	__bss_start = ADDR(.bss);
	__bss_end = ALIGN(__bss_start + SIZEOF(.bss), 0x8);
	_gp = ADDR(.got) + 0x7fc0;
}
