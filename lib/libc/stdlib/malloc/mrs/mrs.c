/*-
 * Copyright (c) 2019 Brett F. Gutstein
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/ktrace.h>
#include <sys/mman.h>
#include <sys/tree.h>
#include <sys/resource.h>
#include <sys/cpuset.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/revoke.h>
#include <cheri/libcaprevoke.h>

#include <machine/vmparam.h>

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <malloc_np.h>
#include <pthread.h>
#include <pthread_np.h>
#include <spinlock.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/elf.h>

#include "libc_private.h"
#include "mrs_utrace.h"

/*
 * Knobs:
 *
 * DEBUG: Print debug statements.
 * PRINT_STATS: Print statistics on exit.
 * PRINT_CAPREVOKE: Print stats for each CHERI revocation.
 * PRINT_CAPREVOKE_MRS: Print details of MRS operation around revocations.
 * CLEAR_ON_ALLOC: Zero allocated regions as they are allocated (for
 *   non-calloc allocation functions).
 * CLEAR_ON_RETURN: Zero allocated regions as they come out of quarantine.
 * CLEAR_ON_FREE: Zero allocated regions as they are given to us.
 * REVOKE_ON_FREE: Perform revocation on free rather than during
 *   allocation routines.
 *
 * Values:
 *
 * QUARANTINE_NUMERATOR / QUARANTINE_DENOMINATOR: Limit the quarantine
 * size to QUARANTINE_NUMERATOR / QUARANTINE_DENOMINATOR times the size
 * of the heap (default 1/4).
 */

#ifdef QUARANTINE_RATIO
#error QUARANTINE_RATIO is obsolete, use QUARANTINE_NUMERATOR/QUARANTINE_DENOMINATOR
#endif
#ifndef QUARANTINE_DENOMINATOR
#define	QUARANTINE_DENOMINATOR	4
#endif
#ifndef QUARANTINE_NUMERATOR
#define	QUARANTINE_NUMERATOR	1
#endif

#define	MALLOCX_LG_ALIGN_BITS	6
#define	MALLOCX_LG_ALIGN_MASK	((1 << MALLOCX_LG_ALIGN_BITS) - 1)
/* Use MALLOCX_ALIGN_GET() if alignment may not be specified in flags. */
#define	MALLOCX_ALIGN_GET_SPECIFIED(flags)				\
    ((size_t)1 << (flags & MALLOCX_LG_ALIGN_MASK))
#define	MALLOCX_ALIGN_GET(flags)					\
    (MALLOCX_ALIGN_GET_SPECIFIED(flags) & (SIZE_T_MAX - 1))

#ifdef SNMALLOC_PRINT_STATS
extern void snmalloc_print_stats(void);
#endif
#ifdef SNMALLOC_FLUSH
extern void snmalloc_flush_message_queue(void);
#endif

#define	MALLOC_QUARANTINE_DISABLE_ENV	"_RUNTIME_REVOCATION_DISABLE"
#define	MALLOC_QUARANTINE_ENABLE_ENV	"_RUNTIME_REVOCATION_ENABLE"
#define	MALLOC_ABORT_DISABLE_ENV	"_RUNTIME_ABORT_DISABLE"
#define	MALLOC_ABORT_ENABLE_ENV		"_RUNTIME_ABORT_ENABLE"

#define	MALLOC_REVOKE_EVERY_FREE_DISABLE_ENV \
	"_RUNTIME_REVOCATION_EVERY_FREE_DISABLE"
#define	MALLOC_REVOKE_EVERY_FREE_ENABLE_ENV \
	"_RUNTIME_REVOCATION_EVERY_FREE_ENABLE"
#define	MALLOC_REVOKE_SYNC_ENV \
	"_RUNTIME_REVOCATION_SYNC_REVOKE"
#define	MALLOC_REVOKE_ASYNC_ENV \
	"_RUNTIME_REVOCATION_ASYNC_REVOKE"
#define	MALLOC_BOUND_CHERI_POINTERS \
	"_RUNTIME_BOUND_CHERI_POINTERS"
#define	MALLOC_NOBOUND_CHERI_POINTERS \
	"_RUNTIME_NOBOUND_CHERI_POINTERS"

#define	MALLOC_QUARANTINE_DENOMINATOR_ENV \
	"_RUNTIME_QUARANTINE_DENOMINATOR"
#define	MALLOC_QUARANTINE_NUMERATOR_ENV \
	"_RUNTIME_QUARANTINE_NUMERATOR"

/*
 * Different allocators give their strong symbols different names.  Hide
 * this implementation detail being the REAL() macro.
 */
#define _REAL_PREPEND(f, pre)	pre##f
#define	_REAL_EVAL(f, pre)	_REAL_PREPEND(f, pre)
#define	REAL(f)	_REAL_EVAL(f, MRS_REAL_PREFIX)

void *REAL(malloc)(size_t);
void REAL(free)(void *);
void *REAL(calloc)(size_t, size_t);
void *REAL(realloc)(void *, size_t);
int REAL(posix_memalign)(void **, size_t, size_t);
void *REAL(aligned_alloc)(size_t, size_t);

/* jemalloc non-standard API */
void *REAL(mallocx)(size_t, int);
void *REAL(rallocx)(void *, size_t, int);
void REAL(dallocx)(void *, int);
void REAL(sdallocx)(void *, size_t, int);

/*
 * XXX: no support for v3 API (allocm, rallocm, sallocm, dallocm, nallocm).
 * The are provided in FreeBSD for backwards compatibility and are not
 * declared in any public header so there should be no users.
 */

/* functions */

static void *mrs_malloc(size_t);
static void mrs_free(void *);
static void *mrs_calloc(size_t, size_t);
static void *mrs_realloc(void *, size_t);
static int mrs_posix_memalign(void **, size_t, size_t);
static void *mrs_aligned_alloc(size_t, size_t);

void *mrs_mallocx(size_t, int);
void *mrs_rallocx(void *, size_t, int);
void mrs_dallocx(void *, int);
void mrs_sdallocx(void *, size_t, int);

void *
malloc(size_t size)
{
	return (mrs_malloc(size));
}

void
free(void *ptr)
{
	return (mrs_free(ptr));
}

void *
calloc(size_t number, size_t size)
{
	return (mrs_calloc(number, size));
}

void *
realloc(void *ptr, size_t size)
{
	return (mrs_realloc(ptr, size));
}

int
posix_memalign(void **ptr, size_t alignment, size_t size)
{
	return (mrs_posix_memalign(ptr, alignment, size));
}

void *
aligned_alloc(size_t alignment, size_t size)
{
	return (mrs_aligned_alloc(alignment, size));
}

void *
mallocx(size_t size, int flags)
{
	return (mrs_mallocx(size, flags));
}

void *
rallocx(void *ptr, size_t size, int flags)
{
	return (mrs_rallocx(ptr, size, flags));
}

void
dallocx(void *ptr, int flags)
{
	return (mrs_dallocx(ptr, flags));
}

void
sdallocx(void *ptr, size_t size, int flags)
{
	return (mrs_sdallocx(ptr, size, flags));
}

/*
 * Defined by CHERIfied mallocs for use with mrs - given a capability returned
 * by the malloc that may have had its bounds shrunk, rederive and return a
 * capability with bounds corresponding to the original allocation.
 *
 * If the passed-in capability is tagged/permissioned and corresponds to some
 * allocation, give back a pointer with that same base whose length corresponds
 * to the underlying allocation size; otherwise return NULL.
 *
 * (For correspondence, check that its base matches the base of an allocation.
 * In practice, check that the offset is zero, which is necessary for the base
 * to match the base of any allocation, and then it is fine to compare the
 * address of the passed-in thing (which is the base) to whatever is necessary.
 * Note that the length of the passed-in capability doesn't matter as long as
 * the allocator uses the underlying size for rederivation or revocation.)
 *
 * This function will give back a pointer with SW_VMEM permission, so mrs can
 * clear its memory and free it back after revocation.  With mrs we assume the
 * attacker can't access this function, and in the post-mrs world it is
 * unnecessary.
 *
 * NB: As long as an allocator's allocations are naturally aligned
 * according to their size, as is the case for most slab/bibop allocators, it
 * is possible to check this condition by verifying that the passed-in
 * base/address is contained in the heap and is aligned to the size of
 * allocations in that heap region (power of 2 size or otherwise).  It may be
 * necessary to do something slightly more complicated, like checking
 * offset from the end of a slab in snmalloc.  In traditional free list
 * allocators, allocation metadata can be used to verify that the passed-in
 * pointer is legit.
 *
 * (Writeup needs more detail about exactly what allocators
 * will give back and expect in terms of base offset etc.)
 *
 * In an allocator that is not using mrs, similar logic should be used to
 * validate and/or rederive pointers and take actions accordingly on the free
 * path and any other function that accepts application pointers.  A pointer
 * passed to free must correspond appropriately as described above.  If it
 * doesn't then no action can be taken or you can abort.
 *
 * malloc_usable_size() and any other function taking in pointers similarly
 * needs validation.
 *
 * NB it is possible to do revocation safely with mrs only using a version of
 * malloc_usable_size() modified to give the size of the underlying allocation -
 * but this was done so that clearing on free could be evaluated easily and
 * so that allocators wouldn't have to accept revoked caps.
 */
void *REAL(malloc_underlying_allocation)(void *);

/* globals */

/*
 * Alignment requirement for allocations so they can be painted in the
 * caprevoke bitmap.
 *
 * XXX VM_CAPREVOKE_GSZ_MEM_NOMAP from machine/vmparam.h
 */
static const size_t CAPREVOKE_BITMAP_ALIGNMENT = sizeof(void *);
static const size_t DESCRIPTOR_SLAB_ENTRIES = 10000;
static const size_t MIN_REVOKE_HEAP_SIZE = 8 * 1024 * 1024;

static volatile const struct cheri_revoke_info *cri;
static size_t page_size;

/* Flags are constant after initialization. */
static void *entire_shadow;
static bool quarantining = true;
static bool revoke_every_free = false;
static bool revoke_async = false;
static bool bound_pointers = false;
static bool abort_on_validation_failure = true;
static bool mrs_initialized = false;

static unsigned int quarantine_denominator = QUARANTINE_DENOMINATOR;
static unsigned int quarantine_numerator = QUARANTINE_NUMERATOR;

static spinlock_t mrs_init_lock = _SPINLOCK_INITIALIZER;
#define	MRS_LOCK(x)	__extension__ ({	\
	if (__isthreaded)			\
		_SPINLOCK(x);			\
})
#define	MRS_UNLOCK(x)	__extension__ ({	\
	if (__isthreaded)			\
		_SPINUNLOCK(x);			\
})

/*
 * Optionally apply strict bounds to pointers returned by malloc() and friends.
 * This is technically UB since it means that the pointer passed to free() is
 * not what we got from the allocator.  However, it may be useful for
 * demonstrating CHERI's spatial safety guarantees in demos and so on.
 *
 * The default behaviour lets the allocator provide pointers with bounds
 * covering the usable size of the allocation, beyond the requested size, which
 * is friendlier to realloc() loops.  With revocation enabled, strict bounds
 * would force a new allocation for each realloc() call, which can hurt quite a
 * bit.
 */
static void *
mrs_bound_pointer(void *p, size_t size)
{
	if (p != NULL && bound_pointers && size > 0)
		p = cheri_setbounds(p, size);
	return (p);
}

struct mrs_descriptor_slab_entry {
	void *ptr;
	size_t size;
};

struct mrs_descriptor_slab {
	int num_descriptors;
	struct mrs_descriptor_slab *next;
	struct mrs_descriptor_slab_entry slab[DESCRIPTOR_SLAB_ENTRIES];
};

struct mrs_quarantine {
	size_t size;
	size_t max_size;
	bool revoking;
	cheri_revoke_epoch_t epoch;	/* valid when revoking */
	struct mrs_descriptor_slab *list;
	TAILQ_ENTRY(mrs_quarantine) next;
};

/* XXX ABA and other issues ... should switch to atomics library */
static struct mrs_descriptor_slab * _Atomic free_descriptor_slabs;

/*
 * amount of memory that the allocator views as allocated (includes
 * quarantine)
 */
static _Atomic size_t allocated_size;
static size_t max_allocated_size;

/*
 * Quarantine arenas for application threads.  At any given time, one is in
 * active use, and the others are being cleaned.
 */
#define	APP_QUARANTINE_ARENAS	2
_Static_assert(APP_QUARANTINE_ARENAS >= 2,
    "APP_QUARANTINE_ARENAS must be at least 2");
static struct mrs_quarantine app_quarantine_store[APP_QUARANTINE_ARENAS];

static struct mrs_quarantine *app_quarantine;
/* Arenas with revocation pending. */
static TAILQ_HEAD(, mrs_quarantine) app_quarantine_revoke_list =
    TAILQ_HEAD_INITIALIZER(app_quarantine_revoke_list);
/* Arenas with revocation complete. */
static TAILQ_HEAD(, mrs_quarantine) app_quarantine_free_list =
    TAILQ_HEAD_INITIALIZER(app_quarantine_free_list);

static void quarantine_flush(struct mrs_quarantine *quarantine);
static void quarantine_move(struct mrs_quarantine *dst,
    struct mrs_quarantine *src);
static void quarantine_revoke(struct mrs_quarantine *quarantine);

static inline __attribute__((always_inline)) void
mrs_puts(const char *p)
{
	size_t n = strlen(p);
	write(2, p, n);
}

/* locks */

#define mrs_lock(mtx) do {						\
	if (pthread_mutex_lock((mtx)) != 0) {				\
		mrs_puts("pthread error\n");				\
		exit(7);						\
	}								\
} while (0)

#define mrs_unlock(mtx) do {						\
	if (pthread_mutex_unlock((mtx)) != 0) {				\
		mrs_puts("pthread error\n");				\
		exit(7);						\
	}								\
} while (0)

/*
 * Hack to initialize mutexes without calling malloc.  Without this, locking
 * operations in allocation functions would cause an infinite loop.  The buf
 * size should be at least sizeof(struct pthread_mutex) from thr_private.h
 */
#define create_lock(name)						\
	pthread_mutex_t name;						\
	char name ## _buf[256] __attribute__((aligned(16)));		\
									\
	void *								\
	name ## _storage(size_t num __unused, size_t size __unused)	\
	{								\
		return (name ## _buf);					\
	}

int _pthread_mutex_init_calloc_cb(pthread_mutex_t *mutex,
    void *(calloc_cb)(size_t, size_t));
#pragma weak _pthread_mutex_init_calloc_cb

int
_pthread_mutex_init_calloc_cb(pthread_mutex_t *mutex,
    void *(calloc_cb)(size_t, size_t))
{
	return (((int (*)(pthread_mutex_t *, void *(*)(size_t, size_t)))
	    __libc_interposing[INTERPOS__pthread_mutex_init_calloc_cb])(mutex,
	    calloc_cb));
}

#define initialize_lock(name)					\
	_pthread_mutex_init_calloc_cb(&name, name ## _storage)

create_lock(app_quarantine_lock);

create_lock(printf_lock);
static void
mrs_printf(char *fmt, ...)
{
	char buf[1024];
	int n = 0, m;

	va_list va;
	va_start(va, fmt);

	m = snprintf(buf, sizeof(buf), "mrs[%d]: ", getpid());
	if (m < 0)
	{
		abort();
	}
	n += m;
	n = (n > sizeof(buf)) ? sizeof(buf) : n;

	m = vsnprintf(buf+n, sizeof(buf)-n, fmt, va);
	if (m < 0)
	{
		abort();
	}
	n += m;
	n = (n > sizeof(buf)) ? sizeof(buf) : n;

	mrs_lock(&printf_lock);
	write(2, buf, n);
	mrs_unlock(&printf_lock);
}

/* debugging */

#ifdef DEBUG
#define mrs_debug_printf(fmt, ...) mrs_printf(fmt, ##__VA_ARGS__)
#else /* DEBUG */
#define mrs_debug_printf(fmt, ...)
#endif /* !DEBUG */

#define	MRS_UTRACE_ENV	"_MRS_UTRACE"

static bool mrs_utrace;

static void
mrs_utrace_log(int event, void *p, size_t s, size_t n, void *r)
{
	struct utrace_mrs ut;
	static const char mrs_utrace_sig[MRS_UTRACE_SIG_SZ] = MRS_UTRACE_SIG;

	memcpy(ut.sig, mrs_utrace_sig, sizeof(ut.sig));
	ut.event = event;
	ut.s = s;
	ut.p = __builtin_cheri_tag_clear(p);
	ut.r = __builtin_cheri_tag_clear(r);
	ut.n = n;
	utrace(&ut, sizeof(ut));
}

#define	MRS_UTRACE(...) do {					\
	if (mrs_utrace)						\
		mrs_utrace_log(__VA_ARGS__);			\
} while (0)

/* utilities */

static struct mrs_descriptor_slab *
alloc_descriptor_slab(void)
{
	if (free_descriptor_slabs == NULL) {
		mrs_debug_printf("alloc_descriptor_slab: mapping new memory\n");
		void *ret = mmap(NULL, sizeof(struct mrs_descriptor_slab),
		    PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
		return ((ret == MAP_FAILED) ? NULL : ret);
	} else {
		mrs_debug_printf("alloc_descriptor_slab: reusing memory\n");
		struct mrs_descriptor_slab *ret = free_descriptor_slabs;

		while (!atomic_compare_exchange_weak(&free_descriptor_slabs,
		    &ret, ret->next))
			;

		ret->num_descriptors = 0;
		return (ret);
	}
}

/*
 * We assume that the consumer of this shim can issue arbitrary malicious
 * malloc/free calls.  To track the total allocated size effectively, we
 * accumulate the length of capabilities as they are returned by mrs_malloc.
 * For the quarantine size, tracking is different in the offload and
 * non-offload cases.  In the non-offload case, capabilities passed in to
 * mrs_free are validated and replaced with a rederived capability to the
 * entire allocation (obtained by calling the underlying allocator's
 * malloc_underlying_allocation() function) before being added to quarantine,
 * so we accumulate the length of capabilities in quarantine post-validation.
 * The result is that for each allocation, the same number is added to the
 * allocated size total and the quarantine size total.  When the quarantine is
 * flushed, the allocated size is reduced by the quarantine size and the
 * quarantine size is reset to zero.
 *
 * In the offload case, the application thread fills a quarantine with
 * unvalidated capabilities passed in to mrs_free() (which may be untagged,
 * duplicates, have shrunk bounds, etc.).  The lengths of these capabilities are
 * accumulated into the quarantine size, which is an approximation and only
 * used to trigger offload processing.  In the offload thread, a separate
 * accumulation is performed using only validated capabilities, and that is used
 * to reduce the allocated size after flushing.
 *
 * Sometimes malloc implementations are recursive in which case we leak some
 * space.  This was observed in snmalloc for allocations of size 0x20.
 */
static inline void
increment_allocated_size(void *allocated)
{
	allocated_size += cheri_getlen(allocated);
	if (allocated_size > max_allocated_size) {
		max_allocated_size = allocated_size;
	}
}

static inline void
clear_region(void *mem, size_t len)
{
	static const size_t ZERO_THRESHOLD = 64;

	/*
	 * For small regions that are qword-multiple-sized, use writes to avoid
	 * memset call.  Alignment should be good in normal cases.
	 */
	if ((len <= ZERO_THRESHOLD) && (len % sizeof(uint64_t) == 0)) {
		for (size_t i = 0; i < (len / sizeof(uint64_t)); i++) {
			/*
			 * volatile needed to avoid memset call by
			 * compiler "optimization"
			 */
			((volatile uint64_t *)mem)[i] = 0;
		}
	} else {
		memset(mem, 0, len);
	}
}

/*
 * Insert a freed allocation into a quarantine with minimal validation; increase
 * quarantine size by the length of the allocation's capability.
 */
static inline void
quarantine_insert(struct mrs_quarantine *quarantine, void *ptr, size_t size)
{
	MRS_UTRACE(UTRACE_MRS_QUARANTINE_INSERT, ptr, size, 0, NULL);
	if (quarantine->list == NULL ||
	    quarantine->list->num_descriptors == DESCRIPTOR_SLAB_ENTRIES) {
		struct mrs_descriptor_slab *ins = alloc_descriptor_slab();
		if (ins == NULL) {
			mrs_puts("quarantine_insert: couldn't allocate new descriptor slab\n");
			exit(7);
		}
		ins->next = quarantine->list;
		quarantine->list = ins;
	}

	if ((__builtin_cheri_perms_get(ptr) & CHERI_PERM_SW_VMEM) == 0) {
		mrs_printf("fatal error: can't insert pointer without SW_VMEM");
		exit(7);
	}

	quarantine->list->slab[quarantine->list->num_descriptors].ptr = ptr;
	quarantine->list->slab[quarantine->list->num_descriptors].size = size;
	quarantine->list->num_descriptors++;

	quarantine->size += size;
	if (quarantine->size > quarantine->max_size) {
		quarantine->max_size = quarantine->size;
	}
}

/*
 * Given a pointer freed by the application, validate it by (1) checking that
 * the pointer has an underlying allocation (was actually allocated by the
 * allocator) and (2) using the bitmap painting function to make sure this
 * pointer is valid and hasn't already been freed or revoked.
 *
 * Returns a capability to the underlying allocation if validation was
 * successful, NULL otherwise.
 *
 * Supports ablation study knobs, returning NULL in case of a short circuit.
 */
static inline void *
validate_freed_pointer(void *ptr)
{

	/*
	 * Untagged check before malloc_underlying_allocation()
	 * catches NULL and other invalid caps that may cause a rude
	 * implementation of malloc_underlying_allocation() to crash.
	 */
	if (!cheri_gettag(ptr)) {
		mrs_debug_printf("validate_freed_pointer: untagged capability addr %p\n",
		    ptr);
		return (NULL);
	}

	void *underlying_allocation = REAL(malloc_underlying_allocation)(ptr);
	if (underlying_allocation == NULL) {
		mrs_debug_printf("validate_freed_pointer: not allocated by underlying allocator\n");
		return (NULL);
	}
	/*mrs_debug_printf("freed underlying allocation %#p\n", underlying_allocation);*/

	/*
	 * Here we use the bitmap to synchronize and make sure that
	 * our guarantee is upheld in multithreaded environments.  We
	 * paint the bitmap to signal to the kernel what needs to be
	 * revoked, but we also gate the operation of bitmap painting,
	 * so that we can only successfully paint the bitmap for some
	 * freed allocation (and let that allocation pass onto the
	 * quarantine list) if it is legitimately allocated on the
	 * heap, not revoked, and not previously queued for
	 * revocation, at the time of painting.
	 *
	 * Essentially at this point we don't want something to end up
	 * on the quarantine list twice.  If that were to happen, we
	 * wouldn't be upholding the principle that prevents heap
	 * aliasing.
	 *
	 * We can't allow a capability to pass painting and end up on
	 * the quarantine list if its region of the bitmap is already
	 * painted.  If that were to happen, the two quarantine list
	 * entries corresponding to that region would be freed
	 * non-atomically, such that we could observe one being freed,
	 * the allocator reallocating the region, then the other being
	 * freed <! ERROR !>.
	 *
	 * We also can't allow a previously revoked capability to pass
	 * painting and end up on the quarantine list.  If that were to
	 * happen, we could observe:
	 *
	 * ptr mrs_freed -> painted in bitmap -> added to quarantine ->
	 * revoked -> cleared in bitmap ->
	 * /THREAD SWITCH/ revoked ptr mrs_freed -> painted in bitmap ->
	 * revoked again -> cleared in bitmap -> freed back to allocator ->
	 * reused /THREAD SWITCH BACK/ -> freed back to allocator <! ERROR !>
	 *
	 * Similarly for untagged capabilities, because then a
	 * malicious user could just construct a capability that takes
	 * the place of revoked ptr (i.e. same address) above.
	 *
	 * We block these behaviors with a bitmap painting function
	 * that takes in a user pointer and the full length of the
	 * allocation.  It will only succeed if, atomically at the
	 * time of painting, (1) the bitmap region is not painted, (2)
	 * the user pointer is tagged, and (3) the user pointer is not
	 * revoked.  If the painting function fails, we short-circuit
	 * and do not add allocation to quarantine.
	 *
	 * We can clear the bitmap after revocation and before freeing
	 * back to the allocator, which "opens" the gate for
	 * revocation of that region to occur again.  It's fine for
	 * clearing not to be atomic with freeing back to the
	 * allocator, though, because between revocation and the
	 * allocator reallocating the region, the user does not have
	 * any valid capabilities to the region by definition.
	 */

	/*
	 * Doesn't matter whether or not the len of underlying_allocation is
	 * actually a 16-byte multiple because all allocations will be 16-byte
	 * aligned.
	 */
	if (caprev_shadow_nomap_set_len(cri->base_mem_nomap, entire_shadow,
	    cheri_getbase(ptr),
	    __builtin_align_up(cheri_getlen(underlying_allocation),
	    CAPREVOKE_BITMAP_ALIGNMENT), ptr)) {
		mrs_debug_printf("validate_freed_pointer: setting bitmap failed\n");
		return (NULL);
	}

	return (underlying_allocation);
}

static inline bool
quarantine_should_flush(struct mrs_quarantine *quarantine, bool is_free)
{
	if (is_free && revoke_every_free)
		return true;

#ifdef REVOKE_ON_FREE
	if (!is_free)
		return false;
#else
	if (is_free)
		return false;
#endif

	if (allocated_size < MIN_REVOKE_HEAP_SIZE)
		return false;

	/*
	 * Flush quarantine if
	 *                                       quarantine_numerator
	 * quarantine->size >= allocated_size * ----------------------
	 *                                      quarantine_denominator
	 *
	 * Avoid division by multiplying both sides by quarantine_numerator.
	 */
	return (quarantine->size * quarantine_denominator >=
	    allocated_size * quarantine_numerator);
}

static void
app_quarantine_remove(struct mrs_quarantine *to, struct mrs_quarantine *src)
{
	quarantine_move(to, src);
	TAILQ_REMOVE(&app_quarantine_revoke_list, src, next);
	src->revoking = false;
	TAILQ_INSERT_TAIL(&app_quarantine_free_list, src, next);
}

/*
 * Kick off an asynchronous revocation pass for the current application
 * quarantine arena, and/or check to see whether a previously scheduled pass has
 * completed.
 *
 * This function assumes that the application quarantine lock is held and will
 * drop it before returning.
 */
static void
app_quarantine_revoke_async(void)
{
	struct mrs_quarantine *curr, *next;
	cheri_revoke_epoch_t epoch;

	/*
	 * Add this arena to the list of pending revocations if it isn't already
	 * there.
	 */
	curr = app_quarantine;
	next = TAILQ_FIRST(&app_quarantine_free_list);
	if (!curr->revoking && next != NULL) {
		TAILQ_REMOVE(&app_quarantine_free_list, next, next);
		app_quarantine = next;

		curr->epoch = cri->epochs.enqueue;
		curr->revoking = true;
		TAILQ_INSERT_TAIL(&app_quarantine_revoke_list, curr, next);
	}
	assert(!TAILQ_EMPTY(&app_quarantine_revoke_list));
	epoch = TAILQ_FIRST(&app_quarantine_revoke_list)->epoch;
	mrs_unlock(&app_quarantine_lock);

	(void)cheri_revoke(CHERI_REVOKE_ASYNC, epoch, NULL);

	/*
	 * Is it possible that some of the pending revocation work has finished?
	 * Flush some of the revoked memory back to the underlying allocator if
	 * so.
	 */
	if (cheri_revoke_epoch_clears(cri->epochs.dequeue, epoch)) {
		struct mrs_quarantine tmp;

		mrs_lock(&app_quarantine_lock);
		next = TAILQ_FIRST(&app_quarantine_revoke_list);
		if (next == NULL) {
			mrs_unlock(&app_quarantine_lock);
			return;
		}
		assert(next->revoking);
		if (!cheri_revoke_epoch_clears(cri->epochs.dequeue,
		    next->epoch)) {
			mrs_unlock(&app_quarantine_lock);
			return;
		}

		app_quarantine_remove(&tmp, next);
		mrs_unlock(&app_quarantine_lock);
		quarantine_flush(&tmp);
	}
}

/*
 * Handle a malloc_revoke_quarantine_force_flush() call when operating in async mode.
 * Perform synchronous revocation for all quarantine arenas, and then revoke
 * the currently active arena.
 */
static void
malloc_revoke_quarantine_force_flush_async(void)
{
	struct mrs_quarantine tmp;

	while (!TAILQ_EMPTY(&app_quarantine_revoke_list)) {
		struct mrs_quarantine *curr;

		curr = TAILQ_FIRST(&app_quarantine_revoke_list);
		app_quarantine_remove(&tmp, curr);
		mrs_unlock(&app_quarantine_lock);
		quarantine_revoke(&tmp);
		mrs_lock(&app_quarantine_lock);
	}
	quarantine_move(&tmp, app_quarantine);
	mrs_unlock(&app_quarantine_lock);
	quarantine_revoke(&tmp);
}

#if defined(PRINT_CAPREVOKE) || defined(PRINT_CAPREVOKE_MRS)
static inline uint64_t
cheri_revoke_get_cyc(void)
{
#if defined(__riscv)
	return (__builtin_readcyclecounter());
#elif defined(__aarch64__)
	uint64_t _val;
	__asm __volatile("mrs %0, cntvct_el0" : "=&r" (_val));
	return (_val);
#else
	return (0);
#endif
}
#endif

#if defined(PRINT_CAPREVOKE)
static inline void
print_cheri_revoke_stats(char *what, struct cheri_revoke_syscall_info *crsi,
    uint64_t cycles)
{
	mrs_printf("mrs caprevoke %s:"
	    " efin=%" PRIu64

	    " psro=%" PRIu32
	    " psrw=%" PRIu32

	    " pfro=%" PRIu32
	    " pfrw=%" PRIu32

	    " pclg=%" PRIu32

	    " pskf=%" PRIu32
	    " pskn=%" PRIu32
	    " psks=%" PRIu32

	    " cfnd=%" PRIu32
	    " cfrv=%" PRIu32

	    " cnuk=%" PRIu32

	    " lscn=%" PRIu32
	    " pmkc=%" PRIu32

	    " pcyc=%" PRIu64
	    " fcyc=%" PRIu64
	    " tcyc=%" PRIu64
	    "\n",

	    what,
	    crsi->epochs.dequeue,

	    crsi->stats.pages_scan_ro,
	    crsi->stats.pages_scan_rw,

	    crsi->stats.pages_faulted_ro,
	    crsi->stats.pages_faulted_rw,

	    crsi->stats.fault_visits,

	    crsi->stats.pages_skip_fast,
	    crsi->stats.pages_skip_nofill,
	    crsi->stats.pages_skip,

	    crsi->stats.caps_found,
	    crsi->stats.caps_found_revoked,

	    crsi->stats.caps_cleared,

	    crsi->stats.lines_scan,
	    crsi->stats.pages_mark_clean,

	    crsi->stats.page_scan_cycles,
	    crsi->stats.fault_cycles,
	    cycles);
}
#endif /* PRINT_CAPREVOKE */

static void
quarantine_flush(struct mrs_quarantine *quarantine)
{
	struct mrs_descriptor_slab *prev = NULL;

	MRS_UTRACE(UTRACE_MRS_QUARANTINE_FLUSH, NULL, 0, 0, NULL);
	for (struct mrs_descriptor_slab *iter = quarantine->list; iter != NULL;
	     iter = iter->next) {
		for (int i = 0; i < iter->num_descriptors; i++) {

			/*
			 * Doesn't matter if the underlying
			 * size isn't a 16-byte multiple
			 * because all allocations will be
			 * 16-byte aligned.
			 */
			size_t len = __builtin_align_up(
			    cheri_getlen(iter->slab[i].ptr),
			    CAPREVOKE_BITMAP_ALIGNMENT);
			caprev_shadow_nomap_clear_len(
			    cri->base_mem_nomap, entire_shadow,
			    cheri_getbase(iter->slab[i].ptr), len);

			/*
			 * Don't construct a pointer to a
			 * previously revoked region until the
			 * bitmap is cleared.
			 */
			atomic_thread_fence(memory_order_release);

#ifdef CLEAR_ON_RETURN
			clear_region(iter->slab[i].ptr,
			    cheri_getlen(iter->slab[i].ptr));
#endif /* CLEAR_ON_RETURN */

			/*
			 * We have a VMEM-bearing cap from
			 * malloc_underlying_allocation.
			 *
			 * XXX: We used to rely on the
			 * underlying allocator to rederive
			 * caps but snmalloc2's CHERI support
			 * doesn't do that by default, so
			 * we'll clear VMEM here.  This feels
			 * wrong, somehow; perhaps we want to
			 * retry with snmalloc1 not doing
			 * rederivation now that we're doing
			 * this?
			 */
			REAL(free)(__builtin_cheri_perms_and(iter->slab[i].ptr,
			    ~CHERI_PERM_SW_VMEM));
		}
		prev = iter;
	}

	size_t utrace_allocated_size = 0;
	if (prev != NULL) {
		/* Free the quarantined descriptors. */
		prev->next = free_descriptor_slabs;
		while (!atomic_compare_exchange_weak(&free_descriptor_slabs,
		    &prev->next, quarantine->list))
			;

		quarantine->list = NULL;
		allocated_size -= quarantine->size;
		utrace_allocated_size += quarantine->size;
		quarantine->size = 0;
	}
	mrs_debug_printf("quarantine_flush: flushed, allocated_size %zu quarantine->size %zu\n",
	    allocated_size, quarantine->size);
	MRS_UTRACE(UTRACE_MRS_QUARANTINE_FLUSH_DONE, NULL, utrace_allocated_size, 0, NULL);
}

/*
 * Perform revocation then iterate through the quarantine and free entries with
 * non-zero underlying size (offload thread sets unvalidated caps to have zero
 * size).
 *
 * Supports ablation study knobs.
 */
static void
quarantine_revoke(struct mrs_quarantine *quarantine)
{
	/* Don't read epoch until all bitmap painting is done. */
	atomic_thread_fence(memory_order_acq_rel);
	cheri_revoke_epoch_t start_epoch = cri->epochs.enqueue;

	MRS_UTRACE(UTRACE_MRS_QUARANTINE_REVOKE, NULL, 0, 0, NULL);
	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, start_epoch)) {
# ifdef PRINT_CAPREVOKE
		struct cheri_revoke_syscall_info crsi = { 0 };
		uint64_t cyc_init, cyc_fini;

		cyc_init = cheri_revoke_get_cyc();
		(void)cheri_revoke(CHERI_REVOKE_TAKE_STATS, epoch, &crsi);
		cyc_fini = cheri_revoke_get_cyc();
		print_cheri_revoke_stats("load-barrier", &crsi,
		    cyc_fini - cyc_init);

		cyc_init = cheri_revoke_get_cyc();
		(void)cheri_revoke(
		    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_TAKE_STATS, epoch,
		    &crsi);
		cyc_fini = cheri_revoke_get_cyc();
		print_cheri_revoke_stats("load-final", &crsi,
		    cyc_fini - cyc_init);

# else /* PRINT_CAPREVOKE */
		(void)cheri_revoke(CHERI_REVOKE_TAKE_STATS, start_epoch, NULL);
		(void)cheri_revoke(
		    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_TAKE_STATS,
		    start_epoch, NULL);
# endif /* !PRINT_CAPREVOKE */
	}
	MRS_UTRACE(UTRACE_MRS_QUARANTINE_REVOKE_DONE, NULL, 0, 0, NULL);
	quarantine_flush(quarantine);
}

static void
quarantine_move(struct mrs_quarantine *dst, struct mrs_quarantine *src)
{
	dst->list = src->list;
	dst->size = src->size;
	dst->max_size = src->max_size;
	src->list = NULL;
	src->size = 0;
}

static void
_internal_quarantine_flush(struct mrs_quarantine *quarantine)
{
#ifdef PRINT_CAPREVOKE_MRS
	mrs_puts("malloc_revoke_quarantine_force_flush\n");
#endif
	quarantine_revoke(quarantine);
#ifdef SNMALLOC_FLUSH
	/* Consume pending messages now in our queue. */
	snmalloc_flush_message_queue();
#endif
#if defined(SNMALLOC_PRINT_STATS)
	snmalloc_print_stats();
#endif
}

int
malloc_revoke_quarantine_force_flush(void)
{
	struct mrs_quarantine local_quarantine;

	if (!quarantining)
		return (ENOTSUP);

	MRS_UTRACE(UTRACE_MRS_MALLOC_REVOKE_QUARANTINE_FORCE_FLUSH, NULL, 0,
	    0, NULL);

	mrs_lock(&app_quarantine_lock);
	if (revoke_async) {
		malloc_revoke_quarantine_force_flush_async();
	} else {
		quarantine_move(&local_quarantine, app_quarantine);
		mrs_unlock(&app_quarantine_lock);
		_internal_quarantine_flush(&local_quarantine);
	}

	return (0);
}

bool
malloc_revoke_enabled(void)
{
	return (quarantining);
}

void
malloc_revoke(void)
{
	(void)malloc_revoke_quarantine_force_flush();
}

bool
malloc_is_revoking(void)
{
	return (quarantining);
}

/*
 * Check whether we should flush based on the quarantine policy and perform the
 * flush if so.  Takes into account whether offload is enabled or not.
 *
 * In the wrapper, we perform these checks at the beginning of allocation
 * routines (so that the allocation routines might use the revoked memory in
 * the non-offload edge case where this could happen) rather than during an
 * mmap call - it might be better to perform this check just as the allocator
 * runs out of memory and before it calls mmap, but this is not possible from
 * the wrapper.
 */
static inline void
check_and_perform_flush(bool is_free)
{
	struct mrs_quarantine local_quarantine;

	/*
	 * Do an unlocked check and bail quickly if the quarantine
	 * does not require flushing.
	 */
	if (!quarantine_should_flush(app_quarantine, is_free))
		return;

	/* Recheck with the lock held. */
	mrs_lock(&app_quarantine_lock);
	if (!quarantine_should_flush(app_quarantine, is_free)) {
		mrs_unlock(&app_quarantine_lock);
		return;
	}

	if (revoke_async) {
		app_quarantine_revoke_async();
	} else {
		quarantine_move(&local_quarantine, app_quarantine);
		mrs_unlock(&app_quarantine_lock);
		_internal_quarantine_flush(&local_quarantine);
	}
}

/* constructor and destructor */

static void
mrs_init_impl_locked(void)
{
	initialize_lock(app_quarantine_lock);
	initialize_lock(printf_lock);

	page_size = getpagesize();
	if ((page_size & (page_size - 1)) != 0) {
		mrs_puts("page_size not a power of 2\n");
		exit(7);
	}

	char *envstr, *end;
	if ((envstr = secure_getenv(MALLOC_QUARANTINE_DENOMINATOR_ENV)) !=
	    NULL) {
		errno = 0;
		quarantine_denominator = strtoul(envstr, &end, 0);
		if (*end != '\0' ||
		    (quarantine_denominator == ULONG_MAX &&
		     errno == ERANGE)) {
			mrs_puts("invalid "
			    MALLOC_QUARANTINE_DENOMINATOR_ENV "\n");
			exit(7);
		}
	}
	if ((envstr = secure_getenv(MALLOC_QUARANTINE_NUMERATOR_ENV)) !=
	    NULL) {
		errno = 0;
		quarantine_numerator = strtoul(envstr, &end, 0);
		if (*end != '\0' ||
		    (quarantine_numerator == ULONG_MAX &&
		     errno == ERANGE)) {
			mrs_puts("invalid "
			    MALLOC_QUARANTINE_NUMERATOR_ENV "\n");
			exit(7);
		}
	}
	if (quarantine_denominator == 0) {
		mrs_puts("quarantine_denominator can not be 0\n");
		exit(7);
	}
	if (quarantine_denominator > 256) {
		/* Could overflow with 56-bits of userspace addresses */
		mrs_puts("quarantine_denominator > 256\n");
		exit(7);
	}
	if (quarantine_numerator == 0) {
		mrs_puts("quarantine_numerator can not be 0\n");
		exit(7);
	}
	if (quarantine_numerator > 256) {
		/* Could overflow with 56-bits of userspace addresses */
		mrs_puts("quarantine_numerator > 256\n");
		exit(7);
	}

	if (!issetugid()) {
		mrs_utrace = (getenv(MRS_UTRACE_ENV) != NULL);
	}

	uint32_t bsdflags;

	if (_elf_aux_info(AT_BSDFLAGS, &bsdflags, sizeof(bsdflags)) == 0) {
		quarantining = ((bsdflags & ELF_BSDF_CHERI_REVOKE) != 0);
		revoke_every_free =
		    ((bsdflags & ELF_BSDF_CHERI_REVOKE_EVERY_FREE) != 0);
		revoke_async = ((bsdflags & ELF_BSDF_CHERI_REVOKE_ASYNC) != 0);
	}

	if (!issetugid()) {
		if (getenv(MALLOC_QUARANTINE_DISABLE_ENV) != NULL) {
			quarantining = false;
		} else if (getenv(MALLOC_QUARANTINE_ENABLE_ENV) != NULL) {
			quarantining = true;
		}

		if (getenv(MALLOC_ABORT_DISABLE_ENV) != NULL)
			abort_on_validation_failure = false;
		else if (getenv(MALLOC_ABORT_ENABLE_ENV) != NULL)
			abort_on_validation_failure = true;

		if (getenv(MALLOC_REVOKE_EVERY_FREE_DISABLE_ENV) != NULL)
			revoke_every_free = false;
		else if (getenv(MALLOC_REVOKE_EVERY_FREE_ENABLE_ENV) != NULL)
			revoke_every_free = true;

		if (getenv(MALLOC_REVOKE_SYNC_ENV) != NULL)
			revoke_async = false;
		else if (getenv(MALLOC_REVOKE_ASYNC_ENV) != NULL)
			revoke_async = true;

		if (getenv(MALLOC_BOUND_CHERI_POINTERS) != NULL)
			bound_pointers = true;
		else if (getenv(MALLOC_NOBOUND_CHERI_POINTERS) != NULL)
			bound_pointers = false;
	}
	if (!quarantining)
		goto nosys;

	if (cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT, NULL,
	    (void **)&cri) != 0) {
		if (errno == ENOSYS) {
			quarantining = false;
			goto nosys;
		}
		mrs_puts("error getting kernel caprevoke counters\n");
		exit(7);
	}

	if (cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMEM_ENTIRE, NULL,
	    &entire_shadow) != 0) {
		mrs_puts("error getting entire shadow cap\n");
		exit(7);
	}

	for (int i = 0; i < APP_QUARANTINE_ARENAS; i++) {
		app_quarantine_store[i].revoking = false;
		if (i > 0) {
			TAILQ_INSERT_TAIL(&app_quarantine_free_list,
			    &app_quarantine_store[i], next);
		}
	}
	app_quarantine = &app_quarantine_store[0];

nosys:
	mrs_initialized = true;

#if defined(PRINT_CAPREVOKE) || defined(PRINT_CAPREVOKE_MRS) || defined(PRINT_STATS)
	mrs_puts(VERSION_STRING);
#endif
}

static void
mrs_init_impl(void)
{
	MRS_LOCK(&mrs_init_lock);
	if (!mrs_initialized)
		mrs_init_impl_locked();
	MRS_UNLOCK(&mrs_init_lock);
}

static __attribute__((always_inline)) void
mrs_init(void)
{
	if (__predict_false(!mrs_initialized))
		mrs_init_impl();
	/* Invariant: mrs_init_impl must initialize mrs or exit. */
	assert(mrs_initialized);
}

__attribute__((__constructor__(100)))
static void
mrs_constructor(void)
{
	mrs_init();
}

#ifdef PRINT_STATS
__attribute__((destructor))
static void
fini(void)
{
	mrs_printf("fini: heap size %zu, max heap size %zu, quarantine size %zu, max quarantine size %zu\n",
	    allocated_size, max_allocated_size, app_quarantine->size,
	    app_quarantine->max_size);
}
#endif /* PRINT_STATS */

/* mrs functions */

static void *
mrs_real_malloc(size_t size)
{
	return (mrs_bound_pointer(REAL(malloc)(size), size));
}

static void *
mrs_malloc(size_t size)
{
	mrs_init();

	if (!quarantining)
		return (mrs_real_malloc(size));

	/*mrs_debug_printf("mrs_malloc: called\n");*/

	check_and_perform_flush(false);

	void *allocated_region;

	/*
	 * Round up here to make sure there is only one allocation per
	 * granule without requiring modifications to the underlying
	 * allocator.
	 *
	 * XXX: If an allocator produced special, non-writable capabilities
	 * for size=0 we might want to pass those calls through, but none
	 * of the currently supported allocators do.
	 */
	if (size < CAPREVOKE_BITMAP_ALIGNMENT)
		allocated_region = mrs_real_malloc(CAPREVOKE_BITMAP_ALIGNMENT);
	else
		allocated_region = mrs_real_malloc(size);
	if (allocated_region == NULL) {
		MRS_UTRACE(UTRACE_MRS_MALLOC, NULL, size, 0,
		    allocated_region);
		return (allocated_region);
	}

#ifdef CLEAR_ON_ALLOC
	clear_region(allocated_region, cheri_getlen(allocated_region));
#endif /* CLEAR_ON_ALLOC */

	increment_allocated_size(allocated_region);

	/*mrs_debug_printf("mrs_malloc: called size 0x%zx, allocation %#p\n",
	    size, allocated_region);*/

	MRS_UTRACE(UTRACE_MRS_MALLOC, NULL, size, 0, allocated_region);
	return (allocated_region);
}

static void *
mrs_real_calloc(size_t number, size_t size)
{
	return (mrs_bound_pointer(REAL(calloc)(number, size), number * size));
}

void *
mrs_calloc(size_t number, size_t size)
{
	size_t tmpsize;

	mrs_init();

	if (!quarantining)
		return (mrs_real_calloc(number, size));

	/*
	 * This causes problems if our library is initialized before
	 * the thread library.
	 */
	/*mrs_debug_printf("mrs_calloc: called\n");*/

	check_and_perform_flush(false);

	void *allocated_region;

	/*
	 * Round up here to make sure there is only one allocation per
	 * granule without requiring modifications to the underlying
	 * allocator.
	 *
	 * XXX: it's conceviable the underlying allocator could reduce
	 * the alignment requirement for small sizes but that seems like an
	 * extraordinarily unlikely and highly questionable optimization.
	 */
	if (!__builtin_mul_overflow(number, size, &tmpsize) &&
	    tmpsize < CAPREVOKE_BITMAP_ALIGNMENT)
		allocated_region = mrs_real_calloc(1, CAPREVOKE_BITMAP_ALIGNMENT);
	else
		allocated_region = mrs_real_calloc(number, size);
	if (allocated_region == NULL) {
		MRS_UTRACE(UTRACE_MRS_CALLOC, NULL, size, number,
		    allocated_region);
		return (allocated_region);
	}

	increment_allocated_size(allocated_region);

	/*
	 * This causes problems if our library is initialized before
	 * the thread library.
	 */
	/*mrs_debug_printf("mrs_calloc: exit called %d size 0x%zx address %p\n", number, size, allocated_region);*/

	MRS_UTRACE(UTRACE_MRS_CALLOC, NULL, size, number, allocated_region);
	return (allocated_region);
}

static int
mrs_real_posix_memalign(void **ptr, size_t alignment, size_t size)
{
	int ret;

	ret = REAL(posix_memalign)(ptr, alignment, size);
	if (ret == 0)
		*ptr = mrs_bound_pointer(*ptr, size);
	return (ret);
}

static int
mrs_posix_memalign(void **ptr, size_t alignment, size_t size)
{
	mrs_init();

	if (!quarantining)
		return (mrs_real_posix_memalign(ptr, alignment, size));

	mrs_debug_printf("mrs_posix_memalign: called ptr %p alignment %zu size %zu\n",
	    ptr, alignment, size);

	check_and_perform_flush(false);

	if (alignment < CAPREVOKE_BITMAP_ALIGNMENT)
		alignment = CAPREVOKE_BITMAP_ALIGNMENT;

	int ret = mrs_real_posix_memalign(ptr, alignment, size);
	if (ret != 0) {
		return (ret);
	}

#ifdef CLEAR_ON_ALLOC
	clear_region(*ptr, cheri_getlen(*ptr));
#endif /* CLEAR_ON_ALLOC */

	increment_allocated_size(*ptr);

	MRS_UTRACE(UTRACE_MRS_POSIX_MEMALIGN, NULL, size, alignment, *ptr);
	return (ret);
}

static void *
mrs_real_aligned_alloc(size_t alignment, size_t size)
{
	return (mrs_bound_pointer(REAL(aligned_alloc)(alignment, size), size));
}

static void *
mrs_aligned_alloc(size_t alignment, size_t size)
{
	mrs_init();

	if (!quarantining)
		return (mrs_real_aligned_alloc(alignment, size));

	mrs_debug_printf("mrs_aligned_alloc: called alignment %zu size %zu\n",
	    alignment, size);

	check_and_perform_flush(false);

	if (alignment < CAPREVOKE_BITMAP_ALIGNMENT)
		alignment = CAPREVOKE_BITMAP_ALIGNMENT;

	void *allocated_region = mrs_real_aligned_alloc(alignment, size);
	if (allocated_region == NULL) {
		MRS_UTRACE(UTRACE_MRS_ALIGNED_ALLOC, NULL, size, alignment,
		    allocated_region);
		return (allocated_region);
	}

#ifdef CLEAR_ON_ALLOC
	clear_region(allocated_region, cheri_getlen(allocated_region));
#endif /* CLEAR_ON_ALLOC */

	increment_allocated_size(allocated_region);

	MRS_UTRACE(UTRACE_MRS_ALIGNED_ALLOC, NULL, size, alignment,
	    allocated_region);
	return (allocated_region);
}

static void *
mrs_real_realloc(void *ptr, size_t size)
{
	return (mrs_bound_pointer(REAL(realloc)(ptr, size), size));
}

/*
 * Replace realloc with a malloc and free to avoid dangling pointers
 * in case of in-place realloc that shrinks the buffer.  If ptr is not
 * a real allocation, its buffer will still get copied into a new
 * allocation.
 */
static void *
mrs_realloc(void *ptr, size_t size)
{
	mrs_init();

	if (!quarantining)
		return (mrs_real_realloc(ptr, size));

	size_t old_size = cheri_getlen(ptr);
	mrs_debug_printf("mrs_realloc: called ptr %p ptr size %zu new size %zu\n",
	    ptr, old_size, size);

	/*
	 * If the new size fits in the current allocation and we won't
	 * be wasting too much space, just return the existing pointer.
	 *
	 * Only try to reclaim space by copying if we'd recover at least
	 * half of the allocated storage.  In other cases we can't tell
	 * the difference between shrinking and linear growth into a
	 * large over-allocation (e.g., growing into snmalloc's
	 * power-of-two buckets by 1K) and we especially want to avoid
	 * copying such cases.
	 */
	if (ptr != NULL && cheri_gettag(ptr) && cheri_getoffset(ptr) == 0 &&
	    size <= old_size && old_size - size <= (old_size >> 1))
		return (ptr);

	void *new_alloc = mrs_malloc(size);

	/*
	 * Per the C standard, copy and free IFF the old pointer is valid
	 * and allocation succeeds.
	 */
	if (ptr != NULL && new_alloc != NULL) {
		memcpy(new_alloc, ptr, size < old_size ? size : old_size);
		mrs_free(ptr);
	}
	MRS_UTRACE(UTRACE_MRS_REALLOC, ptr, size, 0, new_alloc);
	return (new_alloc);
}

static void
mrs_free(void *ptr)
{
	void *ins;

	assert(mrs_initialized || ptr == NULL);

	if (!quarantining)
		return (REAL(free)(ptr));

	/*mrs_debug_printf("mrs_free: called address %p\n", ptr);*/

	MRS_UTRACE(UTRACE_MRS_FREE, ptr, 0, 0, 0);

	if (ptr == NULL)
		return;

	/*
	 * If not offloading, validate the passed-in cap here and
	 * replace it with the cap to its underlying allocation.
	 */
	ins = validate_freed_pointer(ptr);
	if (ins == NULL) {
		mrs_debug_printf("mrs_free: validation failed\n");
		if (abort_on_validation_failure)
			abort();
		else
			return;
	}

#ifdef CLEAR_ON_FREE
	bzero(cheri_setoffset(ptr, 0), cheri_getlen(ptr));
#endif

	mrs_lock(&app_quarantine_lock);
	quarantine_insert(app_quarantine, ins, cheri_getlen(ins));
	mrs_unlock(&app_quarantine_lock);

	check_and_perform_flush(true);
}

static void *
mrs_real_mallocx(size_t size, int flags)
{
	return (mrs_bound_pointer(REAL(mallocx)(size, flags), size));
}

void *
mrs_mallocx(size_t size, int flags)
{
	size_t align = MALLOCX_ALIGN_GET(flags);
	void *ret;

	mrs_init();

	if (!quarantining)
		return (mrs_real_mallocx(size, flags));

	if (align <= CAPREVOKE_BITMAP_ALIGNMENT)
		ret = mrs_malloc(size);
	else if (mrs_posix_memalign(&ret, size, align) != 0)
		ret = NULL;

#ifndef CLEAR_ON_ALLOC
	/* Clear if requested and we aren't clearing above. */
	if (ret != NULL && (flags & MALLOCX_ZERO) != 0)
		clear_region(ret, cheri_getlen(ret));
#endif
	return (ret);
}

static void *
mrs_real_rallocx(void *ptr, size_t size, int flags)
{
	return (mrs_bound_pointer(REAL(rallocx)(ptr, size, flags), size));
}

void *
mrs_rallocx(void *ptr, size_t size, int flags)
{
	void *new_alloc;
	size_t old_size;

	mrs_init();

	if (!quarantining)
		return (mrs_real_rallocx(ptr, size, flags));

	old_size = cheri_getlen(ptr);

	mrs_debug_printf("%s: called ptr %p ptr size %zu new size %zu\n",
	    __func__, ptr, old_size, size);

	/*
	 * Allocate an appropriately-aligned, potentially-zeroed space.
	 * In principle might be more efficent to only zero the end, but
	 * this isn't a widly used API so just waste a little memory
	 * bandwidth to make things similar.
	 */
	new_alloc = mrs_mallocx(size, flags);

	/*
	 * Per the C standard, copy and free IFF the old pointer is valid
	 * and allocation succeeds.
	 */
	if (ptr != NULL && new_alloc != NULL) {
		memcpy(new_alloc, ptr, size < old_size ? size : old_size);
		mrs_free(ptr);
	}
	MRS_UTRACE(UTRACE_MRS_REALLOC, ptr, size, 0, new_alloc);
	return (new_alloc);
}

void
mrs_dallocx(void *ptr, int flags)
{
	/* XXX: snmalloc just ignores flags.  */
	mrs_free(ptr);
}

void
mrs_sdallocx(void *ptr, size_t size, int flags)
{
	/*
	 * XXX: snmalloc just frees ignoring flags so do the same for
	 * simplicity.
	 */
	mrs_free(ptr);
}
