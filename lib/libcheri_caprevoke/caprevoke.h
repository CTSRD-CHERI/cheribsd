#ifndef LIBCHERI_CAPREVOKE_H
#define LIBCHERI_CAPREVOKE_H

#include <stddef.h>
#include <sys/caprevoke.h>

int caprev_shadow_nomap_set(uint64_t * __capability sb,
                            void * __capability obj);

void caprev_shadow_nomap_clear(uint64_t * __capability sb,
                               void * __capability obj);

/* Utility functions for testing */
void caprev_shadow_nomap_offsets(vaddr_t ob, size_t len,
                                 ptrdiff_t *fwo, ptrdiff_t *lwo);
void caprev_shadow_nomap_masks(vaddr_t ob, size_t len,
                               uint64_t *fwm, uint64_t *lwm);

#endif
