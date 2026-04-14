#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include "../scan_and_stash/scan_stash.h"
#include "../scan_and_stash/scan_stash_secret.h"
#include "scan_stashIO.h"
#include "scan_stash_ace_context.h"

#define DEV_FILE_H "scan_stash_ace_ctrl"

// Compile time checks to ensure we don't end up in serious trouble.
_Static_assert(sizeof(struct secret) == 64, "struct secret size");
_Static_assert(__alignof__(struct secret) == 64, "struct secret align");

// ACE enabled flag
bool ace_enabled = false;

static int
scan_stash_ace_open(struct cdev *dev __unused, int flags __unused,
    int devtype __unused, struct thread *td __unused)
{
	printf("scan_stash_ace: device opened\n");
	return 0;
}

static int
scan_stash_ace_ioctl(struct cdev *cd, u_long cmd, char *arg, int flags,
    struct thread *td)
{
	int ret = 0;

	switch (cmd) {
	case SIFT_SCAN_AND_STASH_IOC_ACE_DISABLE:
		printf("SIFT_SCAN_AND_STASH_IOC_ACE_DISABLE = %lu...\n",
		    SIFT_SCAN_AND_STASH_IOC_ACE_DISABLE);
		ace_enabled = false;
		break;

	case SIFT_SCAN_AND_STASH_IOC_ACE_ENABLE:
		printf("SIFT_SCAN_AND_STASH_IOC_ACE_ENABLE = %lu...\n",
		    SIFT_SCAN_AND_STASH_IOC_ACE_ENABLE);
		ace_enabled = true;
		break;

	default:
		printf("I'm here in the default case of sas ACE...\n");
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static struct cdevsw sash_cdevsw = {
	.d_name = DEV_FILE_H,
	.d_version = D_VERSION,
	.d_flags = D_TRACKCLOSE,
	.d_open = scan_stash_ace_open,
	.d_ioctl = scan_stash_ace_ioctl,
};

static struct cdev *sash_dev;

static int
scan_stash_ace_loader(struct module *m __unused, int what, void *arg __unused)
{
	int error = 0;

	switch (what) {
	case MOD_LOAD:
		printf("sash device: loading...\n");
		error = make_dev_p(MAKEDEV_CHECKNAME, &sash_dev, &sash_cdevsw,
		    NULL, UID_ROOT, GID_WHEEL, 0644, DEV_FILE_H);
		printf("sash device: %s %s. (error val: %d)\n", DEV_FILE_H,
		    error == 0 ? "loaded" : "broken", error);
		break;

	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		destroy_dev(sash_dev);
		printf("\nsash device: unloaded.\n");
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return error;
}

DEV_MODULE(scan_stash_ace, scan_stash_ace_loader, NULL);

// We must declare its version so that the scan_stash module can depend on it.
MODULE_VERSION(scan_stash_ace, 1);
