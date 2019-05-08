#pragma once
#include_next <endian.h>
#include <stdint.h>
/* Work around error: initializer element is not a compile-time constant
 *
 * In some glibc versions (e.g. 2.28) htole16() expands to a call to an inline
 * function. Clang will complain that this is not a compile time constant if
 * it is used as a global struct initializer.
 * Define them as simple macros instead. This is not quite as good since it
 * won't catch any type errors when calling the macro (e.g. it now happily
 * accepts pointers) but for the purpose of bootstrapping some tools this
 * should be fine.
 */
#define __uint16_identity(x) ((uint16_t)x)
#define __uint32_identity(x) ((uint32_t)x)
#define __uint64_identity(x) ((uint64_t)x)
