/*
 * krevoke_test.c - A simple FreeBSD kernel module template that defines a sysctl hook.
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <cheri/cheric.h>
#include <vm/uma.h>

static uma_zone_t krevoke_zone;

struct krevoke_block {
	vm_offset_t magic;
	struct krevoke_block *next;
};

#define	CHECK(cond, msg)				\
	if (!(cond))					\
		uprintf("FAIL:" msg "\n")

/*
 * Trigger UMA zone revocation test.
 * This is expected to succeed if CHERI_CAPREVOKE_KERN is enabled and
 * fail otherwise.
 */
static int
uma_krevoke_test_handler(SYSCTL_HANDLER_ARGS)
{
	struct krevoke_block *kb0, *kb1;
	int error = 0;
	int value = 0;

	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || req->newptr == NULL) {
		return (error);
	}

	uprintf("uma_krevoke_test: begin krevoke test\n");

	kb0 = uma_zalloc(krevoke_zone, M_WAITOK);
	kb1 = uma_zalloc(krevoke_zone, M_WAITOK);

	kb1->next = kb0;

	uma_zfree(krevoke_zone, kb0);

	// Force revoke pass
	// uma_revoke_now();
	CHECK(!cheri_gettag(kb1->next), "Revoked ptr is valid");

	uprintf("uma_krevoke_test: krevoke test done\n");

	return (error);
}

// Reuse the _debug namespace for this
SYSCTL_NODE(_debug, OID_AUTO, krevoke, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "krevoke debug namespace");

SYSCTL_PROC(_debug_krevoke, OID_AUTO, uma_krevoke_test,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    NULL, 0, uma_krevoke_test_handler, "I", "Trigger krevoke test");


static int
krevoke_init(void)
{
	krevoke_zone = uma_zcreate("krevoke_zone", sizeof(struct krevoke_block),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_KREVOKE);

	return (0);
}

static void
krevoke_cleanup(void)
{
	uma_zdestroy(krevoke_zone);
}

static int
krevoke_test_modevent(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		error = krevoke_init();
		if (error != 0)
			break;
		uprintf("krevoke_test: Kernel module loaded.\n");
		break;
	case MOD_UNLOAD:
		krevoke_cleanup();
		uprintf("krevoke_test: Kernel module unloaded.\n");
		break;
	default:
		error = EOPNOTSUPP;
		break;
    }

    return (error);
}

// Define the module metadata.
static moduledata_t krevoke_test_mod = {
    "krevoke_test",         // Module name
    krevoke_test_modevent,  // Event handler function
    NULL                    // Extra data (not used)
};

// Declare the module to the kernel.
DECLARE_MODULE(krevoke_test, krevoke_test_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
