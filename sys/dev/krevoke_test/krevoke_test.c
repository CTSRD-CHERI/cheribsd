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

static uma_zone_t krevoke_small_zone;
static uma_zone_t krevoke_medium_zone;
static uma_zone_t krevoke_large_zone;

/* Common krevoke block header */
struct krevoke_block {
	void *ptr;
};

/* This paints a single bit in the shadow bitmap */
struct krevoke_small_block {
	void *ptr;
};

/* This paints a 2 words in the shadow bitmap */
struct krevoke_medium_block {
	void *ptr;
	uintptr_t pad[sizeof(uint64_t) * NBBY + 1];
};

/* This paints a 4 words in the shadow bitmap */
struct krevoke_large_block {
	void *ptr;
	uintptr_t pad[3 * sizeof(uint64_t) * NBBY + 1];
};

#define	CHECK(cond, msg)				\
	if (!(cond)) {					\
		uprintf("FAIL:" msg "\n");		\
		return (EINVAL);			\
	}

#define	KREVOKE_TEST1(fn, arg)						\
	if (fn((arg))) {						\
		fail = true;						\
		uprintf("FAIL: " __XSTRING(fn) "(" __XSTRING(arg) ")\n"); \
	} else {							\
		uprintf("PASS: " __XSTRING(fn) "(" __XSTRING(arg) ")\n"); \
	}

/*
 * Test revocation for different zone sizes.
 */
static int
test_uma_krevoke_zone(uma_zone_t zone)
{
	struct krevoke_block *kb0, *kb1;

	kb0 = uma_zalloc(zone, M_WAITOK);
	CHECK((cheri_getperm(kb0) & CHERI_PERM_SW_KMEM) == 0,
	    "kb0: SW_KMEM is set");
	uprintf("%s: allocated kb0 at %#p\n", __func__, kb0);
	kb1 = uma_zalloc(zone, M_WAITOK);
	CHECK((cheri_getperm(kb1) & CHERI_PERM_SW_KMEM) == 0,
	    "kb1: SW_KMEM is set");
	uprintf("%s: allocated kb1 at %#p\n", __func__, kb1);

	kb1->ptr = kb0;

	uprintf("%s: free(kb0)\n", __func__);
	uma_zfree(zone, kb0);

	// Force revoke pass
	// uma_revoke_now();
	uprintf("%s: check revoked kb1->ptr\n", __func__);
	CHECK(!cheri_gettag(kb1->ptr), "Revoked ptr is valid");

	return (0);
}

/*
 * Trigger UMA zone revocation test.
 * This is expected to succeed if CHERI_CAPREVOKE_KERN is enabled and
 * fail otherwise.
 */
static int
krevoke_test_handler(SYSCTL_HANDLER_ARGS)
{
	bool fail = false;
	int error = 0;
	int value = 0;

	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || req->newptr == NULL) {
		return (error);
	}

	uprintf("uma_krevoke_test: begin krevoke test\n");

	KREVOKE_TEST1(test_uma_krevoke_zone, krevoke_small_zone);
	KREVOKE_TEST1(test_uma_krevoke_zone, krevoke_medium_zone);
	KREVOKE_TEST1(test_uma_krevoke_zone, krevoke_large_zone);

	if (fail)
		error = EINVAL;

	return (error);
}

// Reuse the _debug namespace for this
SYSCTL_NODE(_debug, OID_AUTO, krevoke, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "krevoke debug namespace");

SYSCTL_PROC(_debug_krevoke, OID_AUTO, krevoke_test,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE,
    NULL, 0, krevoke_test_handler, "I", "Trigger krevoke test");


static int
krevoke_init(void)
{
	krevoke_small_zone = uma_zcreate("krevoke_s_zone",
	    sizeof(struct krevoke_small_block), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, UMA_ZONE_KREVOKE);

	krevoke_medium_zone = uma_zcreate("krevoke_m_zone",
	    sizeof(struct krevoke_medium_block), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, UMA_ZONE_KREVOKE);

	krevoke_large_zone = uma_zcreate("krevoke_l_zone",
	    sizeof(struct krevoke_large_block), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, UMA_ZONE_KREVOKE);

	return (0);
}

static void
krevoke_cleanup(void)
{
	uma_zdestroy(krevoke_small_zone);
	uma_zdestroy(krevoke_medium_zone);
	uma_zdestroy(krevoke_large_zone);
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
