
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include <dev/ic/ns16550.h>

#include "debug.h"
#include "mem.h"
#include "uart_emul.h"

void init_uart(struct vmctx *);

static void
mmio_uart_intr_assert(void *arg)
{
	struct vmctx *ctx = arg;

	vm_assert_irq(ctx, 32);
}

static void
mmio_uart_intr_deassert(void *arg)
{
	struct vmctx *ctx = arg;

	vm_deassert_irq(ctx, 32);
}

static int
mmio_uart_mem_handler(struct vmctx *ctx, int vcpu, int dir, uint64_t addr,
		     int size, uint64_t *val, void *arg1, long arg2)
{
	struct uart_softc *sc = arg1;
	long reg;

	reg = (addr - arg2) >> 2;
	if (dir == MEM_F_WRITE) {
		uart_write(sc, reg, *val);
	} else {
		*val = uart_read(sc, reg);
	}

	return (0);
}

void
init_uart(struct vmctx *ctx)
{
	struct uart_softc *sc;
	struct mem_range mr;
	int error;

	sc = uart_init(mmio_uart_intr_assert, mmio_uart_intr_deassert, ctx);
	if (uart_set_backend(sc, "stdio") != 0) {
		EPRINTLN("Unable to initialize backend '%s' for "
		    "mmio uart", "stdio");
		assert(0);
	}

	bzero(&mr, sizeof(struct mem_range));
	mr.name = "uart";
	mr.base = 0x10000;
	mr.size = PAGE_SIZE;
	mr.flags = MEM_F_RW;
	mr.handler = mmio_uart_mem_handler;
	mr.arg1 = sc;
	mr.arg2 = mr.base;
	error = register_mem(&mr);
	assert(error == 0);
}
