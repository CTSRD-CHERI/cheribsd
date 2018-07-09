//===-- hwasan_allocator.h ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of HWAddressSanitizer.
//
//===----------------------------------------------------------------------===//

#ifndef HWASAN_ALLOCATOR_H
#define HWASAN_ALLOCATOR_H

#include "sanitizer_common/sanitizer_common.h"

namespace __hwasan {

struct HwasanThreadLocalMallocStorage {
  uptr quarantine_cache[16];
  // Allocator cache contains atomic_uint64_t which must be 8-byte aligned.
  ALIGNED(8) uptr allocator_cache[96 * (512 * 8 + 16)];  // Opaque.
  void CommitBack();

 private:
  // These objects are allocated via mmap() and are zero-initialized.
  HwasanThreadLocalMallocStorage() {}
};

struct Metadata;

class HwasanChunkView {
 public:
  HwasanChunkView() : block_(0), metadata_(nullptr) {}
  HwasanChunkView(uptr block, Metadata *metadata)
      : block_(block), metadata_(metadata) {}
  bool IsValid() const;        // Checks if it points to a valid allocated chunk
  bool IsAllocated() const;    // Checks if the memory is currently allocated
  uptr Beg() const;            // First byte of user memory
  uptr End() const;            // Last byte of user memory
  uptr UsedSize() const;       // Size requested by the user
  u32 GetAllocStackId() const;
  u32 GetFreeStackId() const;
 private:
  uptr block_;
  Metadata *const metadata_;
};

HwasanChunkView FindHeapChunkByAddress(uptr address);

} // namespace __hwasan

#endif // HWASAN_ALLOCATOR_H
