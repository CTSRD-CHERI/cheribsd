/*
 * Revocation bitmap manipulation operations.
 */

// XXX This can't possibly be right.  Should vmparam.h be checking for
// something else?
#ifndef CPU_CHERI
#define CPU_CHERI
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include <cheri/cheric.h>

#include <sys/param.h>
#include <sys/caprevoke.h>
#include <machine/cherireg.h>
#include <machine/pte.h>
#include <machine/vmparam.h>
#include "caprevoke.h"

static ptrdiff_t caprev_shadow_nomap_first_word_offset(vaddr_t base);
static ptrdiff_t caprev_shadow_nomap_last_word_offset(vaddr_t base, size_t len);
static uint64_t  caprev_shadow_nomap_first_word_mask(vaddr_t base, size_t len);
static uint64_t  caprev_shadow_nomap_last_word_mask(vaddr_t base, size_t len);

  /*
   * Given a capability to an object, derive the offset relative to the base of
   * the fine-grained bitmap where the first word would be located.
   */

static ptrdiff_t
caprev_shadow_nomap_first_word_offset(vaddr_t base)
{
  return (ptrdiff_t)(base / VM_CAPREVOKE_GSZ_MEM_NOMAP
                          / 8
                          / sizeof(uint64_t)) * sizeof(uint64_t);
}

static ptrdiff_t
caprev_shadow_nomap_last_word_offset(vaddr_t base, size_t len)
{
  if (len == 0)
    return caprev_shadow_nomap_first_word_offset(base);

  return (ptrdiff_t)((base + len - 1)
                          / VM_CAPREVOKE_GSZ_MEM_NOMAP
                          / 8
                          / sizeof(uint64_t)) * sizeof(uint64_t);
}

  /*
   * Derive the mask to be or'd in to the first word to mark the object's
   * bottom granules as revoked.
   */

static uint64_t
caprev_shadow_nomap_first_word_mask(vaddr_t base, size_t len)
{
  uint64_t res;

  /* What's the least significant bit's position within the word? */
  int lsb = (base / VM_CAPREVOKE_GSZ_MEM_NOMAP) % (8 * sizeof(uint64_t));

  if (caprev_shadow_nomap_first_word_offset(base) ==
      caprev_shadow_nomap_last_word_offset(base, len)) {
    /* The object occupies only some bits in the first word */

    int setwidth = len / VM_CAPREVOKE_GSZ_MEM_NOMAP;

    if (lsb + setwidth == 64) {
      /* Object fills this word completely, but does not spill to the next */

      res = ~(((uint64_t)1 << lsb) - 1);
    } else {
      res = (   ~(((uint64_t)1 << (lsb + setwidth)) - 1)
             ^ (~(((uint64_t)1 << lsb             ) - 1)));
    }
  } else {
    /* The object runs off the end of this word. */

    res = ~(((uint64_t)1 << lsb) - 1);
  }

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return __builtin_bswap64(res);
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return res;
#else
# error
#endif
}

static uint64_t
caprev_shadow_nomap_last_word_mask(vaddr_t base, size_t len)
{
  uint64_t res;

  if (caprev_shadow_nomap_first_word_offset(base) ==
      caprev_shadow_nomap_last_word_offset(base, len)) {

    /* 
     * There are no more bits to set that haven't been taken care of by the the
     * first word, so just return 0.
     */

    return 0;
  }

  int msb = ((base + len - 1) / VM_CAPREVOKE_GSZ_MEM_NOMAP) % (8 * sizeof(uint64_t));

  if (msb == 63) {
    /* This object runs to the end of its last word */

    return ~(uint64_t)0;
  }

  res = ((uint64_t)1 << (msb+1)) - 1;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return __builtin_bswap64(res);
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return res;
#else
# error
#endif
}

  /*
   * Exposed for testing, but hopefully inlined into the actual update
   * functions below.
   *
   * XXX Slightly less polluting of the external namespace than having all four
   * functions available, maybe?
   */

void
caprev_shadow_nomap_offsets(vaddr_t ob, size_t len, ptrdiff_t *fwo, ptrdiff_t *lwo)
{
  *fwo = caprev_shadow_nomap_first_word_offset(ob);
  *lwo = caprev_shadow_nomap_last_word_offset(ob, len);
}

void
caprev_shadow_nomap_masks(vaddr_t ob, size_t len, uint64_t *fwm, uint64_t *lwm)
{
  *fwm = caprev_shadow_nomap_first_word_mask(ob, len);
  *lwm = caprev_shadow_nomap_last_word_mask(ob, len);
}

  /*
   * A helper function for some things both setting and clearing shadow masks
   * need up front.
   */

static inline void
caprev_shadow_nomap_common_pfx(uint64_t * __capability sb, void * __capability obj,
             vaddr_t *ob, size_t *len, ptrdiff_t *fwo, ptrdiff_t *lwo,
             uint64_t * __capability *fw
            )
{
  *ob = (__cheri_addr vaddr_t)obj;
  *len = cheri_getlen(obj);

  caprev_shadow_nomap_offsets(*ob, *len, fwo, lwo);

  *fw = cheri_setaddress(sb, VM_CAPREVOKE_BM_MEM_NOMAP + *fwo);
}

  /*
   * Mark an object for revocation using the indicated capability to the
   * correct fragment of the shadow bitmap.
   *
   * The masks here are additive: they're going to be OR'd with the shadow.
   *
   * Returns 0 on success or 1 if the calling free() should skip this
   * capability, as it has either become de-tagged or is at least partially
   * already marked in the bitmap (as might happen, for example, with a
   * racing second call to free on the same pointer).
   */

int
caprev_shadow_nomap_set(uint64_t * __capability sb, void * __capability obj)
{
  vaddr_t ob;
  size_t len;
  ptrdiff_t fwo, lwo;
  uint64_t * __capability fw;

  caprev_shadow_nomap_common_pfx(sb, obj, &ob, &len, &fwo, &lwo, &fw);

  uint64_t fwm = caprev_shadow_nomap_first_word_mask(ob, len);

  uint64_t asmres = 0;

  /*
   * The first word is tricky to handle, since we use it to gate frees,
   * ensuring that double-frees are idempotent.  There are two reasons we might
   * bail out:
   *
   *   - another thread has quarantined this object (bits already set)
   *
   *   - this object has been revoked while we held a pointer to it in free()
   *   (and so its tag has been stripped)
   *
   * We have to check the tag stripping inside the ll/sc we use to update the
   * shadow bitmask so that we interlock against the stop-the-world (and maybe
   * read-side) phases of revocation.
   *
   * It's possible the SC fails for neither of the above reasons, of course,
   * not the least of which is that a concurrent thread might be mutating the
   * shadow.  In that case, just go around again.
   *
   * We're going to do this dance with some inline assembler (sigh), because
   * it's a little much to expect C to understand!
   */
#ifdef __mips__

  // t0: the local, manipulated copy of the shadow
  // t1: temp value

  // XXX Why is someone inserting nops in my carefully-written assembler? :(

  __asm__ __volatile__ (
      "1:\n\t"
      "clld $t0, %[fw]\n\t"             // Load linked the first word

      "and $t1, $t0, %[fwm]\n\t"        // Jump out if shadow set
      "bnez $t1, 2f\n\t"
      "nop\n\t"                         // [delay]

      "cbtu %[obj], 2f\n\t"             // Jump out if object detagged

      "or $t0, $t0, %[fwm]\n\t"         // bitwise or in the mask [delay]

      "cscd %[asmres], $t0, %[fw]\n\t"  // SC the updated mask
      "bnez %[asmres], 2f\n\t"          // Jump out on success
      "nop\n\t"                         // [delay]

      "j 1b\n\t"                        // Go again if SC failed
      "nop\n\t"

      "2:\n\t"
    : // output operands
      [asmres] "+r" (asmres)
    : // input operands
      [obj]    "C"  (obj),
      [fw]     "C"  (fw),
      [fwm]    "r"  (fwm)
     : // clobbers
       "t0", "t1", "memory"
  );
#else
#  error Unable to mark bitmaps on this architecture
#endif

  /*
   * In the "Jump out" cases above, %[asmres] will hold the value 0, either
   * from initialization or because a cscd instruction was unsuccessful on a
   * prior iteration.  Only if we don't jump out and successfully exit the loop
   * will asmres be 1.
   */
  if (asmres == 0) {
    return 1;
  }

  if (lwo != fwo) {

    /*
     * If this object straddles a word boundary, the first and last word offets
     * will not be equal; the last word might also need special handling.
     */

    uint64_t * __capability lw = cheri_setaddress(sb,
                                    VM_CAPREVOKE_BM_MEM_NOMAP + lwo);
    uint64_t lwm = caprev_shadow_nomap_last_word_mask(ob, len);

    /*
     * We might overlap a concurrent object's attempt to mutate bits in the
     * last word, so do the OR atomically unless we're setting the whole word,
     * in which case, the write cannot possibly race.
     */

    if (lwm != ~(uint64_t)0) {
      atomic_fetch_or_explicit((_Atomic(uint64_t) * __capability)lw, lwm,
                               memory_order_relaxed);
    } else {
      *lw = ~(uint64_t)0;
    }

    /*
     * Any words between the first and last we can just set all at once;
     * there's nothing else to see here.
     */

    ptrdiff_t wo = fwo + sizeof(uint64_t);
    uint64_t * __capability sbo = fw + 1;
    for (; wo < lwo; wo += sizeof(uint64_t), sbo++) {
      *sbo = ~(uint64_t)0;
    }
  }

  /*
   * There is no need to store-barrier or any such here; we can enforce store
   * order before grabbing the epoch clock for this *chunk* of the quarantine.
   * By ensuring that we make all cores aware of our bits before looking at the
   * clock, we guarantee that the revocation epoch(s) upon which we are waiting
   * will be done with at least our stores visible.
   */

  return 0;
}

  /*
   * Clear an object from the shadow bitmap.
   *
   * The masks here are subtractive: they're going to be AND'd with the shadow.
   */

void
caprev_shadow_nomap_clear(uint64_t * __capability sb, void * __capability obj)
{
  vaddr_t ob;
  size_t len;
  ptrdiff_t fwo, lwo;
  uint64_t * __capability fw;

  caprev_shadow_nomap_common_pfx(sb, obj, &ob, &len, &fwo, &lwo, &fw);

  uint64_t fwm = ~caprev_shadow_nomap_first_word_mask(ob, len);

  /*
   * The first word must be handled atomically, so that it interlocks
   * with the atomic manipulation in caprev_shadow_nomap_set.
   */
  atomic_fetch_and_explicit((_Atomic(uint64_t) * __capability)fw, fwm,
                            memory_order_relaxed);

  if (lwo != fwo) {

    uint64_t * __capability lw = cheri_setaddress(sb,
                                    VM_CAPREVOKE_BM_MEM_NOMAP + lwo);
    uint64_t lwm = ~caprev_shadow_nomap_last_word_mask(ob, len);

    /*
     * The last word may also need to be handled atomically.
     */

    if (lwm != 0) {
      atomic_fetch_and_explicit((_Atomic(uint64_t) * __capability)lw, lwm,
                                memory_order_relaxed);
    } else {
      *lw = 0;
    }

    /*
     * Any words between the first and last we can just clear all at once.
     */

    ptrdiff_t wo = fwo + sizeof(uint64_t);
    uint64_t * __capability sbo = fw + 1;
    for (; wo < lwo; wo += sizeof(uint64_t), sbo++) {
      *sbo = (uint64_t)0;
    }
  }

  /*
   * There is no need to store-barrier or any such here either.  It suffices to
   * store-barrier at the end of whatever set of objects is being cleared from
   * the shadow, before those objects may be released to the application.
   */
}
