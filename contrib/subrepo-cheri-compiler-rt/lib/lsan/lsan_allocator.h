//=-- lsan_allocator.h ----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
// Allocator for standalone LSan.
//
//===----------------------------------------------------------------------===//

#ifndef LSAN_ALLOCATOR_H
#define LSAN_ALLOCATOR_H

#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "lsan_common.h"

namespace __lsan {

void *Allocate(const StackTrace &stack, usize size, usize alignment,
               bool cleared);
void Deallocate(void *p);
void *Reallocate(const StackTrace &stack, void *p, usize new_size,
                 usize alignment);
usize GetMallocUsableSize(const void *p);

template<typename Callable>
void ForEachChunk(const Callable &callback);

void GetAllocatorCacheRange(uptr *begin, uptr *end);
void AllocatorThreadFinish();
void InitializeAllocator();

const bool kAlwaysClearMemory = true;

struct ChunkMetadata {
  u8 allocated : 8;  // Must be first.
  ChunkTag tag : 2;
#if SANITIZER_WORDSIZE == 64
  uptr requested_size : 54;
#else
  uptr requested_size : 32;
  uptr padding : 22;
#endif
  u32 stack_trace_id;
};

#if defined(__mips64) || defined(__aarch64__) || defined(__i386__) || \
    defined(__arm__)
template <typename AddressSpaceViewTy>
struct AP32 {
  static const vaddr kSpaceBeg = 0;
  static const u64 kSpaceSize = SANITIZER_MMAP_RANGE_SIZE;
  static const usize kMetadataSize = sizeof(ChunkMetadata);
  typedef __sanitizer::CompactSizeClassMap SizeClassMap;
  static const usize kRegionSizeLog = 20;
  using AddressSpaceView = AddressSpaceViewTy;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  static const usize kFlags = 0;
};
template <typename AddressSpaceView>
using PrimaryAllocatorASVT = SizeClassAllocator32<AP32<AddressSpaceView>>;
using PrimaryAllocator = PrimaryAllocatorASVT<LocalAddressSpaceView>;
#elif defined(__x86_64__) || defined(__powerpc64__) || defined(__s390x__)
# if SANITIZER_FUCHSIA
const vaddr kAllocatorSpace = ~(uptr)0;
const usize kAllocatorSize  =  0x40000000000ULL;  // 4T.
# elif defined(__powerpc64__)
const vaddr kAllocatorSpace = 0xa0000000000ULL;
const usize kAllocatorSize  = 0x20000000000ULL;  // 2T.
#elif defined(__s390x__)
const vaddr kAllocatorSpace = 0x40000000000ULL;
const usize kAllocatorSize = 0x40000000000ULL;  // 4T.
# else
const vaddr kAllocatorSpace = 0x600000000000ULL;
const usize kAllocatorSize  = 0x40000000000ULL;  // 4T.
# endif
template <typename AddressSpaceViewTy>
struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
  static const vaddr kSpaceBeg = kAllocatorSpace;
  static const usize kSpaceSize = kAllocatorSize;
  static const usize kMetadataSize = sizeof(ChunkMetadata);
  typedef DefaultSizeClassMap SizeClassMap;
  typedef NoOpMapUnmapCallback MapUnmapCallback;
  static const usize kFlags = 0;
  using AddressSpaceView = AddressSpaceViewTy;
};

template <typename AddressSpaceView>
using PrimaryAllocatorASVT = SizeClassAllocator64<AP64<AddressSpaceView>>;
using PrimaryAllocator = PrimaryAllocatorASVT<LocalAddressSpaceView>;
#endif

template <typename AddressSpaceView>
using AllocatorASVT = CombinedAllocator<PrimaryAllocatorASVT<AddressSpaceView>>;
using Allocator = AllocatorASVT<LocalAddressSpaceView>;
using AllocatorCache = Allocator::AllocatorCache;

Allocator::AllocatorCache *GetAllocatorCache();

int lsan_posix_memalign(void **memptr, usize alignment, usize size,
                        const StackTrace &stack);
void *lsan_aligned_alloc(usize alignment, usize size, const StackTrace &stack);
void *lsan_memalign(usize alignment, usize size, const StackTrace &stack);
void *lsan_malloc(usize size, const StackTrace &stack);
void lsan_free(void *p);
void *lsan_realloc(void *p, usize size, const StackTrace &stack);
void *lsan_reallocarray(void *p, usize nmemb, usize size,
                        const StackTrace &stack);
void *lsan_calloc(usize nmemb, usize size, const StackTrace &stack);
void *lsan_valloc(usize size, const StackTrace &stack);
void *lsan_pvalloc(usize size, const StackTrace &stack);
usize lsan_mz_size(const void *p);

}  // namespace __lsan

#endif  // LSAN_ALLOCATOR_H
