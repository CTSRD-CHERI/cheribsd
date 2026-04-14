#ifndef SCAN_STASH_ACE_CONTEXT_H
#define SCAN_STASH_ACE_CONTEXT_H

#include "../scan_and_stash/scan_stash.h"

struct scan_stash_ace_context {
	char **kptr_addr;
	char * __capability *uptr_addr;
	int *len_addr;
	char * __capability *ustack_ctx_addr;

	bool checked;
	bool triggered;
	bool early_return;
	const uint8_t *return_value;
};

void scan_stash_ace(struct scan_stash_ace_context *ctx);

#endif
