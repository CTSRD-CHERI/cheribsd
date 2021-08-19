//===-- sanitizer_allocator_internal.h --------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This allocator is used inside run-times.
//
//===----------------------------------------------------------------------===//

#ifndef SANITIZER_ALLOCATOR_INTERNAL_H
#define SANITIZER_ALLOCATOR_INTERNAL_H

#include "sanitizer_allocator.h"
#include "sanitizer_internal_defs.h"

namespace __sanitizer {

// FIXME: Check if we may use even more compact size class map for internal
// purposes.
typedef CompactSizeClassMap InternalSizeClassMap;

struct AP32 {
  static const vaddr kSpaceBeg = 0;
  static const u64 kSpaceSize = SANITIZER_MMAP_RANGE_SIZE;
  static const usize kMetadataSize = 0;
  typedef InternalSizeClassMap SizeClassMap;
  static const usize kRegionSizeLog = 20;
  using AddressSpaceView = LocalAddressSpaceView;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  static const usize kFlags = 0;
};
typedef SizeClassAllocator32<AP32> PrimaryInternalAllocator;

typedef CombinedAllocator<PrimaryInternalAllocator,
                          LargeMmapAllocatorPtrArrayStatic>
    InternalAllocator;
typedef InternalAllocator::AllocatorCache InternalAllocatorCache;

void *InternalAlloc(usize size, InternalAllocatorCache *cache = nullptr,
                    usize alignment = 0);
void *InternalRealloc(void *p, usize size,
                      InternalAllocatorCache *cache = nullptr);
void *InternalReallocArray(void *p, usize count, usize size,
                           InternalAllocatorCache *cache = nullptr);
void *InternalCalloc(usize count, usize size,
                     InternalAllocatorCache *cache = nullptr);
void InternalFree(void *p, InternalAllocatorCache *cache = nullptr);
InternalAllocator *internal_allocator();

} // namespace __sanitizer

#endif // SANITIZER_ALLOCATOR_INTERNAL_H
