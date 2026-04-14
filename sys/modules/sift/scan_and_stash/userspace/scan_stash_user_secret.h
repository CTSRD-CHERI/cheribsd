#ifndef SCAN_STASH_SECRET_H
#define SCAN_STASH_SECRET_H

// Both the kernel ACE module AND the userspace code load this same header file
// in order to agree upon the definition of this structure.

// The struct to hold the secret made in userland (and the kernel ACE uses it).
// NOTE: This will be packed into exactly 64 bytes when aligned on a 64 byte
// boundary.
struct __attribute__((aligned(64))) secret
{
  // This will contain the string: "=== BEGIN SECRET ==="
  char secret_top_str[20];    // equiv to 5 uint32_t entries (20 bytes)

  union secret_data {         // equiv to 6 uint32_t entries (24 bytes)
    uint8_t secret_u8s[24];
    uint16_t secret_u16s[12];
    uint32_t secret_u32s[6];
  } secret_data;

  // This will contain the string: "==== END SECRET ===="
  char secret_bot_str[20];    // equiv to 5 unit32_t entries (20 bytes)
};

#endif
