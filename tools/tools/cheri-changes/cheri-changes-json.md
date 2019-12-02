CHERI change annotations
========================

Files changed for CHERI (either CHERI support of CheriABI,
pure-capability programs) in CheriBSD are annotated with JSON in
comments.  The following example shows all the current annotations.

```
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20180626,
 *   "target_type": "header, kernel, lib, or prog"
 *   "changes": [
 *     "calling_convention",
 *     "hashing",
 *     "ioctl:misc",
 *     "ioctl:net",
 *     "iovec-macros",
 *     "kernel_sig_types",
 *     "monotonicity",
 *     "platform",
 *     "pointer_alignment",
 *     "pointer_as_integer",
 *     "pointer_bit_flags",
 *     "integer_provenance",
 *     "pointer_provenance",
 *     "pointer_shape",
 *     "support",
 *     "subobject_bounds",
 *     "sysctl",
 *     "uintptr_interp_offset",
 *     "unsupported",
 *     "user_capabilities",
 *     "virtual_address",
 *     "other",
 *     "kdb"
 *   ],
 *   "change_comment": "",
 *   "hybrid_specific": false
 * }
 * CHERI CHANGES END
 */
```

## Fields

`updated`: Date in YYYYMMDD the comment was updated in UTC.  Intended
for used by validation tools.

`target_type`: What is this file used for
 * `header` - System headers defining language runtime and kernel
   interfaces.
 * `kernel` - Files that are part of the kernel.
 * `lib` - Integral to a library (or shared code linked to multiple
   programs).
 * `prog` - Linked to a program.

`changes`: Zero or more tags indicating the types of changes.  Current
values are:

 * `calling_convention` - Changes required by the CHERI-MIPS calling
   convention such as declaring arguments in prototypes and va_args and
   non-va_args functions having different register use.
 * `hashing` - Use of pointer addresses in a hash.  In practice, a subset
   of `virtual address, but common enough to call out.
 * `ioctl:misc` - (kernel) Changes to support ioctls with capability pointers
   in their arguments.
 * `ioctl:net` - (kernel) Like `ioctl:misc` but covering network interface
   configuration.
 * `iovec-macros` - (kernel) Use of macros to initialize and manipulate
   `struct iovec`.  A subset of `user_capabilities`.
 * `kernel_sig_types` - (kernel) Changes to signal related types to store
   signal handlers as poineters  A subset of `user_capabilities`.
 * `monotonicity` - Need to retrieve a capability with greater range or
   permissions from a lesser capability.
 * `platform` - Changes related to the CHERI platform(s) that are not
   CHERI specific.
 * `pointer_alignment` - Aligning (or checking the alignment of) the
   virtual address pointed to by a capability.
 * `pointer_as_integer` - Storing integers in pointer types or
   fabricating pointers from integers (often without any intent to use said
   pointers).
 * `pointer_bit_flags` - Storing and retrieving flags from the lower
   bits of strongly-aligned pointers.
 * `integer_provenance` - Avoiding casts or misaligned storage that does
   not preserve tags.
 * `pointer_provenance` - Deriving pointers from the wrong source.  A
   common(ish) optimization in updating pointers from `realloc()` by
   incrementing the old pointer by the difference of the old and new
   pointers.
 * `pointer_shape` - Working around issues caused by larger pointers
   such as increased alignment.  Also dealing with conflation of the
   size of pointers and the size of the virtual address space.
 * `subobject_bounds` - Adding support for tight sub-object bounds - such
   as adding opt-out annotations for code that uses `containerof()`, etc.
 * `support` - Adding support for CHERI.
 * `sysctl` - (kernel) Sysctl compatability support for CheriABI.
 * `uintptr_interp_offset` - Changes required due to the uintptr_t offset
   interpretation instead of the address interpretation.
 * `unsupported` - Working around unsupported features such as combining
   adjacent `mmap()` allocations, fixed `mmap()` allocations, or `sbrk()`.
 * `user_capabilities` - (kernel) Changes related to userspace pointers
   becoming capabilities including changes to variable, struct member, etc
   types and changes to copyin/out calls etc.
 * `virtual_address` - Need to work with the virtual address (not the
   offset) of capabilities.
 * `kdb` - Changes required for kernel debugging.
 * `other` - Other unrelated changes.

`change_comment`: Optional comment describing changes.

`hybrid_specific`: Defined to `true` if the change only applies to the
hybrid ABI.  Set to `false` or not present otherwise.

## Conventions

All lines of the annotation have the same prefix as is before `CHERI CHANGES
START` e.g.:

```
 * CHERI CHANGES START
 * { ... }
 * CHERI CHANGES END
```
or
```
# CHERI CHANGES START
# { ... }
# CHERI CHANGES END
```
This facilitates stripping local comment characters regardless of the
file type.
