/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011-2012 Robert N. M. Watson
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

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/cons.h>
#include <sys/endian.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/reboot.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/tty.h>
#include <sys/types.h>

#include <cheri/cheric.h>

#include <ddb/ddb.h>

#include <dev/altera/jtag_uart/altera_jtag_uart.h>

static SYSCTL_NODE(_hw, OID_AUTO, altera_jtag_uart,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Altera JTAG UART configuration knobs");

/*
 * One-byte buffer as we can't check whether the UART is readable without
 * actually reading from it, synchronised by a spinlock; this lock also
 * synchronises access to the I/O ports for non-atomic sequences.  These
 * symbols are public so that the TTY layer can use them when working on an
 * instance of the UART that is also a low-level console.
 */
char		aju_cons_buffer_data;
int		aju_cons_buffer_valid;
int		aju_cons_jtag_present;
u_int		aju_cons_jtag_missed;
struct mtx	aju_cons_lock;

/* UART memory mapping base */
char *aju_io_base;

/*
 * Low-level console driver functions.
 */
static cn_probe_t	aju_cnprobe;
static cn_init_t	aju_cninit;
static cn_term_t	aju_cnterm;
static cn_getc_t	aju_cngetc;
static cn_putc_t	aju_cnputc;
static cn_grab_t	aju_cngrab;
static cn_ungrab_t	aju_cnungrab;

/*
 * JTAG sets the ALTERA_JTAG_UART_CONTROL_AC bit whenever it accesses the
 * FIFO.  This allows us to (sort of) tell when JTAG is present, so that we
 * can adopt lossy, rather than blocking, behaviour when JTAG isn't there.
 * When it is present, we do full flow control.  This delay is how long we
 * wait to see if JTAG has really disappeared when finding a full buffer and
 * no AC bit set.
 */
#define	ALTERA_JTAG_UART_AC_POLL_DELAY	10000
static u_int	altera_jtag_uart_ac_poll_delay =
		    ALTERA_JTAG_UART_AC_POLL_DELAY;
SYSCTL_UINT(_hw_altera_jtag_uart, OID_AUTO, ac_poll_delay,
    CTLFLAG_RW, &altera_jtag_uart_ac_poll_delay, 0,
    "Maximum delay waiting for JTAG present flag when buffer is full");

/*
 * I/O routines lifted from Deimos.  This is not only MIPS-specific, but also
 * BERI-specific, as we're hard coding the address at which we expect to
 * find the Altera JTAG UART and using it unconditionally.  We use these
 * low-level routines so that we can perform console I/O long before newbus
 * has initialised and devices have attached.  The TTY layer of the driver
 * knows about this, and uses the console-layer spinlock instead of the
 * TTY-layer lock to avoid confusion between layers for the console UART.
 *
 * XXXRW: The only place this inter-layer behaviour breaks down is if the
 * low-level console is used for polled read while the TTY driver is also
 * looking for input.  Probably we should also share buffers between layers.
 */

/*
 * Get memory-mapped JTAG UART register address in
 * uncached physically mapped memory.
 */
static inline char *
mips_aju_register_addr(vm_paddr_t regoff)
{

	return (aju_io_base + regoff);
}

static inline uint32_t
mips_ioread_uint32(char *raddr)
{
	uint32_t v;

#ifdef __CHERI_PURE_CAPABILITY__
	__asm__ __volatile__ ("clw %0, $zero, 0(%1)" : "=r" (v) : "C" (raddr));
#else
	__asm__ __volatile__ ("lw %0, 0(%1)" : "=r" (v) : "r" (raddr));
#endif
	return (v);
}

static inline void
mips_iowrite_uint32(char *raddr, uint32_t v)
{

#ifdef __CHERI_PURE_CAPABILITY__
	__asm__ __volatile__ ("csw %0, $zero, 0(%1)" : : "r" (v), "C" (raddr));
#else
	__asm__ __volatile__ ("sw %0, 0(%1)" : : "r" (v), "r" (raddr));
#endif
}

/*
 * Little-endian versions of 32-bit I/O routines.
 */
static inline uint32_t
mips_ioread_uint32le(char *raddr)
{

	return (le32toh(mips_ioread_uint32(raddr)));
}

static inline void
mips_iowrite_uint32le(char *raddr, uint32_t v)
{

	mips_iowrite_uint32(raddr, htole32(v));
}

/*
 * Low-level read and write register routines; the Altera UART is little
 * endian, so we byte swap 32-bit reads and writes.
 */
static inline uint32_t
aju_cons_data_read(void)
{

	return (mips_ioread_uint32le(mips_aju_register_addr(
	    ALTERA_JTAG_UART_DATA_OFF)));
}

static inline void
aju_cons_data_write(uint32_t v)
{

	mips_iowrite_uint32le(mips_aju_register_addr(
	    ALTERA_JTAG_UART_DATA_OFF), v);
}

static inline uint32_t
aju_cons_control_read(void)
{

	return (mips_ioread_uint32le(mips_aju_register_addr(
	    ALTERA_JTAG_UART_CONTROL_OFF)));
}

static inline void
aju_cons_control_write(uint32_t v)
{

	mips_iowrite_uint32le(mips_aju_register_addr(
	    ALTERA_JTAG_UART_CONTROL_OFF), v);
}

/*
 * Slightly higher-level routines aware of buffering and flow control.
 */
static int
aju_cons_readable(void)
{
	uint32_t v;

	AJU_CONSOLE_LOCK_ASSERT();

	if (aju_cons_buffer_valid)
		return (1);
	v = aju_cons_data_read();
	if ((v & ALTERA_JTAG_UART_DATA_RVALID) != 0) {
		aju_cons_buffer_valid = 1;
		aju_cons_buffer_data = (v & ALTERA_JTAG_UART_DATA_DATA);
		return (1);
	}
	return (0);
}

static void
aju_cons_write(char ch)
{
	uint32_t v;

	AJU_CONSOLE_LOCK_ASSERT();

	/*
	 * The flow control logic here is somewhat subtle: we want to wait for
	 * write buffer space only while JTAG is present.  However, we can't
	 * directly ask if JTAG is present -- just whether it's been seen
	 * since we last cleared the ALTERA_JTAG_UART_CONTROL_AC bit.  As
	 * such, implement a polling loop in which we both wait for space and
	 * try to decide whether JTAG has disappeared on us.  We will have to
	 * wait one complete polling delay to detect that JTAG has gone away,
	 * but otherwise shouldn't wait any further once it has gone.  And we
	 * had to wait for buffer space anyway, if it was there.
	 *
	 * If JTAG is spotted, reset the TTY-layer miss counter so console-
	 * layer clearing of the bit doesn't trigger a TTY-layer
	 * disconnection.
	 *
	 * XXXRW: Notice the inherent race with hardware: in clearing the
	 * bit, we may race with hardware setting the same bit.  This can
	 * cause real-world reliability problems due to lost output on the
	 * console.
	 */
	v = aju_cons_control_read();
	if (v & ALTERA_JTAG_UART_CONTROL_AC) {
		aju_cons_jtag_present = 1;
		aju_cons_jtag_missed = 0;
		v &= ~ALTERA_JTAG_UART_CONTROL_AC;
		aju_cons_control_write(v);
	}
	while ((v & ALTERA_JTAG_UART_CONTROL_WSPACE) == 0) {
		if (!aju_cons_jtag_present)
			return;
		DELAY(altera_jtag_uart_ac_poll_delay);
		v = aju_cons_control_read();
		if (v & ALTERA_JTAG_UART_CONTROL_AC) {
			aju_cons_jtag_present = 1;
			v &= ~ALTERA_JTAG_UART_CONTROL_AC;
			aju_cons_control_write(v);
		} else
			aju_cons_jtag_present = 0;
	}
	aju_cons_data_write(ch);
}

static char
aju_cons_read(void)
{

	AJU_CONSOLE_LOCK_ASSERT();

	while (!aju_cons_readable());
	aju_cons_buffer_valid = 0;
	return (aju_cons_buffer_data);
}

/*
 * Implementation of a FreeBSD low-level, polled console driver.
 */
static void
aju_cnprobe(struct consdev *cp)
{

	sprintf(cp->cn_name, "%s%d", AJU_TTYNAME, 0);
	cp->cn_pri = (boothowto & RB_SERIAL) ? CN_REMOTE : CN_NORMAL;
}

static void
aju_cninit(struct consdev *cp)
{
	uint32_t v;

	AJU_CONSOLE_LOCK_INIT();

	AJU_CONSOLE_LOCK();
	aju_io_base = MIPS_PHYS_TO_XKPHYS_UNCACHED(BERI_UART_BASE);
#ifdef __CHERI_PURE_CAPABILITY__
	aju_io_base = cheri_ptrperm(aju_io_base,
		8, CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE);
#endif
	v = aju_cons_control_read();
	v &= ~ALTERA_JTAG_UART_CONTROL_AC;
	aju_cons_control_write(v);
	AJU_CONSOLE_UNLOCK();
}

static void
aju_cnterm(struct consdev *cp)
{

}

static int
aju_cngetc(struct consdev *cp)
{
	int ret;

	AJU_CONSOLE_LOCK();
	ret = aju_cons_read();
	AJU_CONSOLE_UNLOCK();
	return (ret);
}

static void
aju_cnputc(struct consdev *cp, int c)
{

	AJU_CONSOLE_LOCK();
	aju_cons_write(c);
	AJU_CONSOLE_UNLOCK();
}

static void
aju_cngrab(struct consdev *cp)
{

}

static void
aju_cnungrab(struct consdev *cp)
{

}

CONSOLE_DRIVER(aju);
// CHERI CHANGES START
// {
//   "updated": 20230509,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "pointer_as_integer",
//     "support",
//     "pointer_provenance"
//   ]
// }
// CHERI CHANGES END
