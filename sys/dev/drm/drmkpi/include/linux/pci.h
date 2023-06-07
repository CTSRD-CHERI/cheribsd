/* Public domain. */

#ifndef	_LINUX_PCI_H_
#define	_LINUX_PCI_H_

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/pciio.h>
#include <sys/rman.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pci_private.h>

#include <machine/resource.h>

#include <linux/list.h>

struct pci_dev;
struct pci_driver;
struct pci_device_id;

#endif	/* _LINUX_PCI_H_ */
