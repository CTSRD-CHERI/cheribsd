//===-- scudo_allocator_combined.h ------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// Scudo Combined Allocator, dispatches allocation & deallocation requests to
/// the Primary or the Secondary backend allocators.
///
//===----------------------------------------------------------------------===//

#ifndef SCUDO_ALLOCATOR_COMBINED_H_
#define SCUDO_ALLOCATOR_COMBINED_H_

#ifndef SCUDO_ALLOCATOR_H_
#error "This file must be included inside scudo_allocator.h."
#endif

template <class PrimaryAllocator, class AllocatorCache,
    class SecondaryAllocator>
class ScudoCombinedAllocator {
 public:
  void init(s32 ReleaseToOSIntervalMs) {
    Primary.Init(ReleaseToOSIntervalMs);
    Secondary.Init();
    Stats.Init();
  }

  // Primary allocations are always MinAlignment aligned, and as such do not
  // require an Alignment parameter.
  void *allocatePrimary(AllocatorCache *Cache, uptr Size) {
    return Cache->Allocate(&Primary, Primary.ClassID(Size));
  }

  // Secondary allocations do not require a Cache, but do require an Alignment
  // parameter.
  void *allocateSecondary(uptr Size, uptr Alignment) {
    return Secondary.Allocate(&Stats, Size, Alignment);
  }

  void deallocatePrimary(AllocatorCache *Cache, void *Ptr) {
    Cache->Deallocate(&Primary, Primary.GetSizeClass(Ptr), Ptr);
  }

  void deallocateSecondary(void *Ptr) {
    Secondary.Deallocate(&Stats, Ptr);
  }

  uptr getActuallyAllocatedSize(void *Ptr, bool FromPrimary) {
    if (FromPrimary)
      return PrimaryAllocator::ClassIdToSize(Primary.GetSizeClass(Ptr));
    return Secondary.GetActuallyAllocatedSize(Ptr);
  }

  void initCache(AllocatorCache *Cache) {
    Cache->Init(&Stats);
  }

  void destroyCache(AllocatorCache *Cache) {
    Cache->Destroy(&Primary, &Stats);
  }

  void getStats(AllocatorStatCounters StatType) const {
    Stats.Get(StatType);
  }

 private:
  PrimaryAllocator Primary;
  SecondaryAllocator Secondary;
  AllocatorGlobalStats Stats;
};

#endif  // SCUDO_ALLOCATOR_COMBINED_H_
