/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Ruslan Bukin <br@bsdpad.com>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <machine/bus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/iicbus/iiconf.h>
#include <dev/iicbus/iicbus.h>

#include <dev/extres/clk/clk.h>

#include <dev/cadence/cdns_i2c.h>

#include "iicbus_if.h"

#define	CDNS_I2C_DEBUG
#undef	CDNS_I2C_DEBUG

#ifdef	CDNS_I2C_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	CDNS_I2C_ISR_MASK	(I2C_ISR_COMP	|\
				 I2C_ISR_DATA	|\
				 I2C_ISR_NACK	|\
				 I2C_ISR_TO	|\
				 I2C_ISR_SLVRDY	|\
				 I2C_ISR_RXOVF	|\
				 I2C_ISR_TXOVF	|\
				 I2C_ISR_RXUNF	|\
				 I2C_ISR_ARBLOST)

struct cdns_i2c_softc {
	device_t	dev;
	struct resource	*res[2];
	struct mtx	mtx;
	int		busy;
	void *		intrhand;
	device_t	iicbus;
	int		hold_flag;
};

static struct ofw_compat_data compat_data[] = {
	{"cdns,i2c-r1p14",	1},
	{NULL,			0}
};

static struct resource_spec cdns_i2c_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE | RF_SHAREABLE },
	{ -1, 0 }
};

#define	CDNS_I2C_TIMEOUT_MAX		0xff

#define	CDNS_I2C_LOCK(sc)		mtx_lock(&(sc)->mtx)
#define	CDNS_I2C_UNLOCK(sc)		mtx_unlock(&(sc)->mtx)
#define	CDNS_I2C_ASSERT_LOCKED(sc)	mtx_assert(&(sc)->mtx, MA_OWNED)

#define	RD4(sc, reg)		bus_read_4((sc)->res[0], (reg))
#define	WR4(sc, reg, val)	bus_write_4((sc)->res[0], (reg), (val))

static int
cdns_i2c_reset(device_t dev, u_char speed, u_char addr, u_char *oldaddr)
{

printf("%s\n", __func__);

	return (0);
}

static void
cdns_i2c_intr_locked(struct cdns_i2c_softc *sc)
{
}

static void
cdns_i2c_intr(void *arg)
{
	struct cdns_i2c_softc *sc;

	sc = (struct cdns_i2c_softc *)arg;

printf("%s\n", __func__);

	CDNS_I2C_LOCK(sc);
	cdns_i2c_intr_locked(sc);
	CDNS_I2C_UNLOCK(sc);
}

static uint32_t
cdns_i2c_wait(struct cdns_i2c_softc *sc, uint32_t mask)
{
	uint32_t timeout;
	uint32_t reg;

	for (timeout = 0; timeout < 100; timeout++) {
		reg = RD4(sc, CDNS_I2C_ISR);
		if (reg & mask)
			break;
		DELAY(100);
	}

	/* Clear interrupt status flags. */
	WR4(sc, CDNS_I2C_ISR, reg & mask);

	return (reg & mask);
}

static int
cdns_i2c_read_data(device_t dev, struct iic_msg *msg)
{
	struct cdns_i2c_softc *sc;
	uint8_t *data;
	uint32_t len;
	uint32_t reg;
	int curr_len;
	uint8_t d;

	sc = device_get_softc(dev);

	dprintf("%s: slave %x len %d\n", __func__, msg->slave, msg->len);

	len = msg->len;
	data = msg->buf;

	reg = RD4(sc, CDNS_I2C_CR);
	if (len > CDNS_I2C_FIFO_DEPTH)
		reg |= I2C_CR_HOLD;
	/* Set the controller in Master receive mode and clear FIFO. */
	reg |= I2C_CR_CLR_FIFO;
	reg |= I2C_CR_RW;
	WR4(sc, CDNS_I2C_CR, reg);

	if (len > CDNS_I2C_TRANSFER_SIZE)
		curr_len = CDNS_I2C_TRANSFER_SIZE;
	else
		curr_len = len;
	WR4(sc, CDNS_I2C_TRANS_SIZE, curr_len);

	/* Start operation.  */
	WR4(sc, CDNS_I2C_ADDR, msg->slave >> 1);

	while (len) {
		if (RD4(sc, CDNS_I2C_ISR) & I2C_ISR_ARBLOST) {
			dprintf("%s: arb lost\n", __func__);
			return (EAGAIN);
		}
		while (RD4(sc, CDNS_I2C_SR) & I2C_SR_RXDV) {
			if ((len < CDNS_I2C_FIFO_DEPTH) && !sc->hold_flag) {
				reg = RD4(sc, CDNS_I2C_CR);
				reg &= ~I2C_CR_HOLD;
				WR4(sc, CDNS_I2C_CR, reg);
			}
			d = RD4(sc, CDNS_I2C_DATA);
			*(data++) = d;
			len --;
			curr_len --;
		}

		if (len && !curr_len) {
			WR4(sc, CDNS_I2C_ADDR, msg->slave >> 1);
			if (len > CDNS_I2C_TRANSFER_SIZE)
				curr_len = CDNS_I2C_TRANSFER_SIZE;
			else
				curr_len = len;
			WR4(sc, CDNS_I2C_TRANS_SIZE, curr_len);
		}
	}

	reg = cdns_i2c_wait(sc, I2C_ISR_COMP | I2C_ISR_ARBLOST);
	if (reg & I2C_ISR_ARBLOST) {
		dprintf("%s: compl reg %x ISR %x\n", __func__, reg,
		    RD4(sc, CDNS_I2C_ISR));
		return (EAGAIN);
	}

	return (0);
}

static int
cdns_i2c_write_data(device_t dev, struct iic_msg *msg)
{
	struct cdns_i2c_softc *sc;
	uint8_t *data;
	uint32_t reg;
	uint32_t len;

	sc = device_get_softc(dev);

	data = msg->buf;
	len = msg->len;

	dprintf("%s: slave %x len %d\n", __func__, msg->slave, msg->len);

	/* Set the controller in Master transmit mode and clear FIFO. */
	reg = RD4(sc, CDNS_I2C_CR);
	if (len > CDNS_I2C_FIFO_DEPTH)
		reg |= I2C_CR_HOLD;
	reg |= I2C_CR_CLR_FIFO;
	reg &= ~I2C_CR_RW;
	WR4(sc, CDNS_I2C_CR, reg);

	WR4(sc, CDNS_I2C_ISR, CDNS_I2C_ISR_MASK);
	WR4(sc, CDNS_I2C_ADDR, msg->slave >> 1);

	while (len --) {
		if (RD4(sc, CDNS_I2C_ISR) & I2C_ISR_ARBLOST) {
			dprintf("%s: arb lost\n", __func__);
			return (EAGAIN);
		}

		WR4(sc, CDNS_I2C_DATA, *(data++));
		if (len &&
		    (RD4(sc, CDNS_I2C_TRANS_SIZE) == CDNS_I2C_FIFO_DEPTH)) {
			panic("here");
		}
	}

	if (sc->hold_flag == 0) {
		reg = RD4(sc, CDNS_I2C_CR);
		reg &= ~I2C_CR_HOLD;
		WR4(sc, CDNS_I2C_CR, reg);
	}

	reg = cdns_i2c_wait(sc, I2C_ISR_COMP | I2C_ISR_ARBLOST);
	if (reg & I2C_ISR_ARBLOST) {
		dprintf("%s: compl reg %x ISR %x\n", __func__, reg,
		    RD4(sc, CDNS_I2C_ISR));
		return (EAGAIN);
	}

	return (0);
}

static int
cdns_i2c_transfer(device_t dev, struct iic_msg *msgs, uint32_t nmsgs)
{
	struct cdns_i2c_softc *sc;
	struct iic_msg *msg;
	uint32_t reg;
	int error;
	int i;

	sc = device_get_softc(dev);

	dprintf("%s: nmsgs %d\n", __func__, nmsgs);

	CDNS_I2C_LOCK(sc);

	while (sc->busy)
		mtx_sleep(sc, &sc->mtx, 0, "i2cbuswait", 0);

	sc->busy = 1;

	if (nmsgs > 1) {
		sc->hold_flag = 1;

		reg = RD4(sc, CDNS_I2C_CR);
		reg |= I2C_CR_HOLD;
		WR4(sc, CDNS_I2C_CR, reg);
	} else
		sc->hold_flag = 0;

retry:
	for (i = 0; i < nmsgs; i++) {
		if (i == (nmsgs - 1))
			sc->hold_flag = 0;
		msg = &msgs[i];
		if (msg->flags & IIC_M_RD)
			error = cdns_i2c_read_data(dev, msg);
		else
			error = cdns_i2c_write_data(dev, msg);

		if (error == EAGAIN)
			goto retry;
	}

	if (error)
		printf("%s: error %d\n", __func__, error);

	sc->busy = 0;

	CDNS_I2C_UNLOCK(sc);
	return (0);
}

static int
cdns_i2c_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Cadence I2C");

	return (BUS_PROBE_DEFAULT);
}

static int
cdns_i2c_attach(device_t dev)
{
	struct cdns_i2c_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, cdns_i2c_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	if (bus_setup_intr(dev, sc->res[1],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, cdns_i2c_intr, sc,
	    &sc->intrhand)) {
		bus_release_resources(dev, cdns_i2c_spec, sc->res);
		device_printf(dev, "cannot setup interrupt handler\n");
		return (ENXIO);
	}

	mtx_init(&sc->mtx, device_get_nameunit(dev), "cdns_i2c", MTX_DEF);

	clk_set_assigned(dev, ofw_bus_get_node(dev));

#if 0
	/* Activate the module clocks. */
	error = clk_get_by_ofw_name(dev, 0, "i2c", &sc->sclk);
	if (error != 0) {
		device_printf(dev, "cannot get i2c clock\n");
		goto fail;
	}
	error = clk_enable(sc->sclk);
	if (error != 0) {
		device_printf(dev, "cannot enable i2c clock\n");
		goto fail;
	}
	/* pclk clock is optional. */
	error = clk_get_by_ofw_name(dev, 0, "pclk", &sc->pclk);
	if (error != 0 && error != ENOENT) {
		device_printf(dev, "cannot get pclk clock\n");
		goto fail;
	}
	if (sc->pclk != NULL) {
		error = clk_enable(sc->pclk);
		if (error != 0) {
			device_printf(dev, "cannot enable pclk clock\n");
			goto fail;
		}
	}
#endif

	reg = RD4(sc, CDNS_I2C_CR);
	printf("%s: original CR %x\n", __func__, reg);

	reg |= 2 << 14;
	reg |= I2C_CR_ACK_EN | I2C_CR_NEA | I2C_CR_MS;
	WR4(sc, CDNS_I2C_CR, reg);

	printf("%s: new CR %x\n", __func__, reg);

	/* A bug workaround in master receiver mode. */
	WR4(sc, CDNS_I2C_TIME_OUT, CDNS_I2C_TIMEOUT_MAX);

	sc->iicbus = device_add_child(dev, "iicbus", -1);
	if (sc->iicbus == NULL) {
		device_printf(dev, "cannot add iicbus child device\n");
		return (ENXIO);
	}

	bus_generic_attach(dev);

	return (0);
}

static int
cdns_i2c_detach(device_t dev)
{
	struct cdns_i2c_softc *sc;
	int error;

	sc = device_get_softc(dev);

	if ((error = bus_generic_detach(dev)) != 0)
		return (error);

	if (sc->iicbus != NULL)
		if ((error = device_delete_child(dev, sc->iicbus)) != 0)
			return (error);

#if 0
	if (sc->sclk != NULL)
		clk_release(sc->sclk);
	if (sc->pclk != NULL)
		clk_release(sc->pclk);
#endif

	if (sc->intrhand != NULL)
		bus_teardown_intr(sc->dev, sc->res[1], sc->intrhand);

	bus_release_resources(dev, cdns_i2c_spec, sc->res);

	mtx_destroy(&sc->mtx);

	return (0);
}

static phandle_t
cdns_i2c_get_node(device_t bus, device_t dev)
{

	return ofw_bus_get_node(bus);
}

static device_method_t cdns_i2c_methods[] = {
	DEVMETHOD(device_probe,		cdns_i2c_probe),
	DEVMETHOD(device_attach,	cdns_i2c_attach),
	DEVMETHOD(device_detach,	cdns_i2c_detach),

	/* OFW methods */
	DEVMETHOD(ofw_bus_get_node,	cdns_i2c_get_node),

	DEVMETHOD(iicbus_callback,	iicbus_null_callback),
	DEVMETHOD(iicbus_reset,		cdns_i2c_reset),
	DEVMETHOD(iicbus_transfer,	cdns_i2c_transfer),

	DEVMETHOD_END
};

static driver_t cdns_i2c_driver = {
	"cdns_i2c",
	cdns_i2c_methods,
	sizeof(struct cdns_i2c_softc),
};

EARLY_DRIVER_MODULE(cdns_i2c, simplebus, cdns_i2c_driver,
    0, 0, BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LATE);
EARLY_DRIVER_MODULE(ofw_iicbus, cdns_i2c, ofw_iicbus_driver,
    0, 0, BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LATE);
MODULE_DEPEND(cdns_i2c, iicbus, 1, 1, 1);
MODULE_VERSION(cdns_i2c, 1);
