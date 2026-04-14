#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/uio.h>
#include <sys/proc.h>

#include "../scan_and_stash/scan_stash.h"
#include "../scan_and_stash/scan_stash_secret.h"
#include "scan_stashIO.h"
#include "scan_stash_ace_context.h"

extern bool ace_enabled;

static const uint8_t *perform_ace(char *kptr, 
                    char * __capability uptr,
                    char * __capability ustack_ctx_ptr,
                    int len)
{
  // Check if you've found a secret made in userland
  void *kptr_v = (void*)kptr;
  struct secret *secret = kptr_v;

  // Here, we are observing bytes from ANY virtual page (thereby from any vm
  // segment) in the user process!
  if (copyin(uptr, kptr, len)) {
    return NULL;
  }

  // Look for the secret delimiter in the 64-byte chunk.
  if (memcmp(secret->secret_top_str, "=== BEGIN SECRET ===", 20) == 0 &&
      memcmp(secret->secret_bot_str, "==== END SECRET ====", 20) == 0)
  {
    // found secret! This will point to 24 bytes of secret data!
    return secret->secret_data.secret_u8s;
  }

  // no secret found
  return NULL;
}

/* NOTE This is a publically exported function for this module. */
__attribute__((noinline))
void scan_stash_ace(struct scan_stash_ace_context *ace_ctx)
{
  ace_ctx->checked = true;

  if (ace_enabled == false) {
    return;
  }

  ace_ctx->triggered = true;
  ace_ctx->return_value = perform_ace(*(ace_ctx->kptr_addr),
                                      (char * __capability)
                                        *(ace_ctx->uptr_addr),
                                      (char * __capability)
                                        *(ace_ctx->ustack_ctx_addr),
                                      *(ace_ctx->len_addr));
  ace_ctx->early_return = true;
}
