# Output a list of entries containing no known changes values.
. - map(select(.changes[] | contains (
  "function_abi",
  "hashing",
  "ioctl:misc",
  "ioctl:net",
  "iovec-macros",
  "kernel_sig_types",
  "kiovec_t",
  "monotonicity",
  "platform",
  "pointer_alignment",
  "pointer_as_integer",
  "pointer_bit_flags",
  "pointer_integrity",
  "pointer_provenance",
  "pointer_size",
  "support",
  "sysctl",
  "unsupported",
  "user_capabilities",
  "virtual_address",
  "other"
)))
