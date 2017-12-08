/*-
 * Copyright (c) 2006-2008 Bruce M. Simpson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>

#include <mips/malta/yamon.h>

#ifdef CHERI_KERNEL
#include <cheri/cheric.h>

/* Wrappers to call into non-purecap ABI YAMON routines */

inline int
_yamon_syscon_read(t_yamon_syscon_id id, void *param, uint32_t size)
{
	int32_t *yamon_func_table = cheri_setoffset(
		cheri_getkdc(), YAMON_FUNC_OFFSET(YAMON_SYSCON_READ_OFS));
	long yamon_syscon_read = (long)*yamon_func_table;
	/* XXX-AM: ideally YAMON_FUNC_OFFSET should return a capability from kseg0_cap */
	/* long yamon_syscon_read = (long)*((int32_t *)YAMON_FUNC_OFFSET(YAMON_SYSCON_READ_OFS)); */
	int value;
	__asm__ __volatile__ (
		".set push\n"
		".set noreorder\n"
		"move $a0, %1\n"
		"cgetbase $a1, %2\n"
		"cgetoffset $t0, %2\n"
		"daddu $a1, $a1, $t0\n"
		"jalr %4\n"
		"move $a2, %3\n"
		"move %0, $v0\n"
		".set pop\n"
		: "=r" (value)
		: "r" (id), "r" (param), "r" (size), "r" (yamon_syscon_read)
		: "memory");
	return value;
}
#endif

char *
yamon_getenv(char *name)
{
	char *value;
	yamon_env_t *p;

	value = NULL;
	for (p = *fenvp; p->name != NULL; ++p) {
	    if (!strcmp(name, p->name)) {
		value = p->value;
		break;
	    }
	}

	return (value);
}

uint32_t
yamon_getcpufreq(void)
{
	uint32_t freq;
	int ret;

	freq = 0;
	ret = YAMON_SYSCON_READ(SYSCON_BOARD_CPU_CLOCK_FREQ_ID, &freq,
	    sizeof(freq));
	if (ret != 0)
		freq = 0;

	return (freq);
}
