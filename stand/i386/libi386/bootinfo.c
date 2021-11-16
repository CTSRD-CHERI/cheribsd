/*-
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
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

#include <stand.h>
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/boot.h>
#include <sys/linker.h>
#include <gfx_fb.h>
#include "bootstrap.h"
#include "libi386.h"
#include "vbe.h"
#include "btxv86.h"

void
bi_load_vbe_data(struct preloaded_file *kfp)
{
	if (!gfx_state.tg_kernel_supported) {
		/*
		 * Loaded kernel does not have vt/vbe backend,
		 * switch console to text mode.
		 */
		if (vbe_available())
			bios_set_text_mode(VGA_TEXT_MODE);
		return;
	}

	if (vbe_available()) {
		file_addmetadata(kfp, MODINFOMD_VBE_FB,
		    sizeof(gfx_state.tg_fb), &gfx_state.tg_fb);
	}
}

int
bi_getboothowto(char *kargs)
{
    char	*curpos, *next, *string;
    int		howto;
    int		vidconsole;

    howto = boot_parse_cmdline(kargs);
    howto |= boot_env_to_howto();

    /* Enable selected consoles */
    string = next = strdup(getenv("console"));
    vidconsole = 0;
    while (next != NULL) {
	curpos = strsep(&next, " ,");
	if (*curpos == '\0')
		continue;
	if (!strcmp(curpos, "vidconsole"))
	    vidconsole = 1;
	else if (!strcmp(curpos, "comconsole"))
	    howto |= RB_SERIAL;
	else if (!strcmp(curpos, "nullconsole"))
	    howto |= RB_MUTE;
    }

    if (vidconsole && (howto & RB_SERIAL))
	howto |= RB_MULTIPLE;

    /*
     * XXX: Note that until the kernel is ready to respect multiple consoles
     * for the boot messages, the first named console is the primary console
     */
    if (!strcmp(string, "vidconsole"))
	howto &= ~RB_SERIAL;

    free(string);

    return(howto);
}

void
bi_setboothowto(int howto)
{

    boot_howto_to_env(howto);
}

/*
 * Copy the environment into the load area starting at (addr).
 * Each variable is formatted as <name>=<value>, with a single nul
 * separating each variable, and a double nul terminating the environment.
 */
vm_offset_t
bi_copyenv(vm_offset_t addr)
{
    struct env_var	*ep;
    
    /* traverse the environment */
    for (ep = environ; ep != NULL; ep = ep->ev_next) {
	i386_copyin(ep->ev_name, addr, strlen(ep->ev_name));
	addr += strlen(ep->ev_name);
	i386_copyin("=", addr, 1);
	addr++;
	if (ep->ev_value != NULL) {
	    i386_copyin(ep->ev_value, addr, strlen(ep->ev_value));
	    addr += strlen(ep->ev_value);
	}
	i386_copyin("", addr, 1);
	addr++;
    }
    i386_copyin("", addr, 1);
    addr++;
    return(addr);
}
