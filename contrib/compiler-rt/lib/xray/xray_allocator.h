//===-- xray_allocator.h ---------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of XRay, a dynamic runtime instrumentation system.
//
// Defines the allocator interface for an arena allocator, used primarily for
// the profiling runtime.
//
//===----------------------------------------------------------------------===//
#ifndef XRAY_ALLOCATOR_H
#define XRAY_ALLOCATOR_H

#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "xray_utils.h"
#include <sys/mman.h>
#include <cstddef>
#include <cstdint>

#ifndef MAP_NORESERVE
// no-op on NetBSD (at least), unsupported flag on FreeBSD basically because unneeded
#define MAP_NORESERVE 0
#endif

namespace __xray {

/// The Allocator type hands out fixed-sized chunks of memory that are
/// cache-line aligned and sized. This is useful for placement of
/// performance-sensitive data in memory that's frequently accessed. The
/// allocator also self-limits the peak memory usage to a dynamically defined
/// maximum.
///
/// N is the lower-bound size of the block of memory to return from the
/// allocation function. N is used to compute the size of a block, which is
/// cache-line-size multiples worth of memory. We compute the size of a block by
/// determining how many cache lines worth of memory is required to subsume N.
///
/// The Allocator instance will manage its own memory acquired through mmap.
/// This severely constrains the platforms on which this can be used to POSIX
/// systems where mmap semantics are well-defined.
///
/// FIXME: Isolate the lower-level memory management to a different abstraction
/// that can be platform-specific.
template <size_t N> struct Allocator {
  // The Allocator returns memory as Block instances.
  struct Block {
    /// Compute the minimum cache-line size multiple that is >= N.
    static constexpr auto Size = nearest_boundary(N, kCacheLineSize);
    void *Data;
  };

private:
  const size_t MaxMemory{0};
  void *BackingStore = nullptr;
  void *AlignedNextBlock = nullptr;
  size_t AllocatedBlocks = 0;
  SpinMutex Mutex{};

  void *Alloc() {
    SpinMutexLock Lock(&Mutex);
    if (UNLIKELY(BackingStore == nullptr)) {
      BackingStore = reinterpret_cast<void *>(
          internal_mmap(NULL, MaxMemory, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 0, 0));
      if (BackingStore == MAP_FAILED) {
        BackingStore = nullptr;
        if (Verbosity())
          Report("XRay Profiling: Failed to allocate memory for allocator.\n");
        return nullptr;
      }

      AlignedNextBlock = BackingStore;

      // Ensure that NextBlock is aligned appropriately.
      auto BackingStoreNum = reinterpret_cast<uintptr_t>(BackingStore);
      auto AlignedNextBlockNum = nearest_boundary(
          reinterpret_cast<uintptr_t>(AlignedNextBlock), kCacheLineSize);
      if (diff(AlignedNextBlockNum, BackingStoreNum) > ptrdiff_t(MaxMemory)) {
        munmap(BackingStore, MaxMemory);
        AlignedNextBlock = BackingStore = nullptr;
        if (Verbosity())
          Report("XRay Profiling: Cannot obtain enough memory from "
                 "preallocated region.\n");
        return nullptr;
      }

      AlignedNextBlock = reinterpret_cast<void *>(AlignedNextBlockNum);

      // Assert that AlignedNextBlock is cache-line aligned.
      DCHECK_EQ(reinterpret_cast<uintptr_t>(AlignedNextBlock) % kCacheLineSize,
                0);
    }

    if ((AllocatedBlocks * Block::Size) >= MaxMemory)
      return nullptr;

    // Align the pointer we'd like to return to an appropriate alignment, then
    // advance the pointer from where to start allocations.
    void *Result = AlignedNextBlock;
    AlignedNextBlock = reinterpret_cast<void *>(
        reinterpret_cast<char *>(AlignedNextBlock) + N);
    ++AllocatedBlocks;
    return Result;
  }

public:
  explicit Allocator(size_t M)
      : MaxMemory(nearest_boundary(M, kCacheLineSize)) {}

  Block Allocate() { return {Alloc()}; }

  ~Allocator() NOEXCEPT {
    if (BackingStore != nullptr) {
      internal_munmap(BackingStore, MaxMemory);
    }
  }
};

} // namespace __xray

#endif // XRAY_ALLOCATOR_H
