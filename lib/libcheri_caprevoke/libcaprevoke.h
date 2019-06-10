#ifndef LIBCHERI_CAPREVOKE_H
#define LIBCHERI_CAPREVOKE_H

#include <stddef.h>
#include <sys/caprevoke.h>

/*
 * The per-object interface protects against concurrent mutation and both
 * intra- and inter-epoch double-frees.
 */
int caprev_shadow_nomap_set_len(uint64_t * __capability sb,
                                vaddr_t ob,
                                size_t len,
                                void * __capability user_obj);

void caprev_shadow_nomap_clear_len(uint64_t * __capability sb,
                                   vaddr_t ob,
                                   size_t len);

int caprev_shadow_nomap_set(uint64_t * __capability sb,
                            void * __capability priv_obj,
                            void * __capability user_obj);

void caprev_shadow_nomap_clear(uint64_t * __capability sb,
                               void * __capability obj);

/*
 * For already interlocked allocators where these protections are not
 * necessary, we also export a "raw" interface, which is especially useful
 * when objects can coalesce in quarantine prior to being staged for
 * revocation, as fewer bitmap writes are necessary.
 */

void caprev_shadow_nomap_set_raw(uint64_t * __capability sb,
                                 vaddr_t heap_start, vaddr_t heap_end);

void caprev_shadow_nomap_clear_raw(uint64_t * __capability sb,
                                   vaddr_t heap_start, vaddr_t heap_end);

/* Utility functions for testing */
void caprev_shadow_nomap_offsets(vaddr_t ob, size_t len,
                                 ptrdiff_t *fwo, ptrdiff_t *lwo);

void caprev_shadow_nomap_masks(vaddr_t ob, size_t len,
                               uint64_t *fwm, uint64_t *lwm);

#endif
