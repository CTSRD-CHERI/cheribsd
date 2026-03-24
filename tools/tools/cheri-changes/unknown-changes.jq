# Output a list of entries containing no known changes values.
. - map(select(.changes[] | contains (
  "bounds_compression",
  "calling_convention",
  "hashing",
  "ioctl:misc",
  "ioctl:net",
  "iovec-macros",
  "kernel_sig_types",
  "monotonicity",
  "platform",
  "pointer_alignment",
  "pointer_as_integer",
  "integer_provenance",
  "pointer_provenance",
  "pointer_shape",
  "support",
  "subobject_bounds",
  "sysctl",
  "unsupported",
  "user_capabilities",
  "virtual_address",
  "other"
)))
