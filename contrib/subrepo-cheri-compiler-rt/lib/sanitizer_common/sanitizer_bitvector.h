//===-- sanitizer_bitvector.h -----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Specializer BitVector implementation.
//
//===----------------------------------------------------------------------===//

#ifndef SANITIZER_BITVECTOR_H
#define SANITIZER_BITVECTOR_H

#include "sanitizer_common.h"

namespace __sanitizer {

// Fixed size bit vector based on a single basic integer.
template <class basic_int_t = usize>
class BasicBitVector {
 public:
  enum SizeEnum : uword { kSize = sizeof(basic_int_t) * 8 };

  usize size() const { return kSize; }
  // No CTOR.
  void clear() { bits_ = 0; }
  void setAll() { bits_ = ~(basic_int_t)0; }
  bool empty() const { return bits_ == 0; }

  // Returns true if the bit has changed from 0 to 1.
  bool setBit(usize idx) {
    basic_int_t old = bits_;
    bits_ |= mask(idx);
    return bits_ != old;
  }

  // Returns true if the bit has changed from 1 to 0.
  bool clearBit(usize idx) {
    basic_int_t old = bits_;
    bits_ &= ~mask(idx);
    return bits_ != old;
  }

  bool getBit(usize idx) const { return (bits_ & mask(idx)) != 0; }

  usize getAndClearFirstOne() {
    CHECK(!empty());
    usize idx = LeastSignificantSetBitIndex(bits_);
    clearBit(idx);
    return idx;
  }

  // Do "this |= v" and return whether new bits have been added.
  bool setUnion(const BasicBitVector &v) {
    basic_int_t old = bits_;
    bits_ |= v.bits_;
    return bits_ != old;
  }

  // Do "this &= v" and return whether any bits have been removed.
  bool setIntersection(const BasicBitVector &v) {
    basic_int_t old = bits_;
    bits_ &= v.bits_;
    return bits_ != old;
  }

  // Do "this &= ~v" and return whether any bits have been removed.
  bool setDifference(const BasicBitVector &v) {
    basic_int_t old = bits_;
    bits_ &= ~v.bits_;
    return bits_ != old;
  }

  void copyFrom(const BasicBitVector &v) { bits_ = v.bits_; }

  // Returns true if 'this' intersects with 'v'.
  bool intersectsWith(const BasicBitVector &v) const {
    return (bits_ & v.bits_) != 0;
  }

  // for (BasicBitVector<>::Iterator it(bv); it.hasNext();) {
  //   usize idx = it.next();
  //   use(idx);
  // }
  class Iterator {
   public:
    Iterator() { }
    explicit Iterator(const BasicBitVector &bv) : bv_(bv) {}
    bool hasNext() const { return !bv_.empty(); }
    usize next() { return bv_.getAndClearFirstOne(); }
    void clear() { bv_.clear(); }
   private:
    BasicBitVector bv_;
  };

 private:
  basic_int_t mask(usize idx) const {
    CHECK_LT(idx, size());
    return (basic_int_t)1UL << idx;
  }
  basic_int_t bits_;
};

// Fixed size bit vector of (kLevel1Size*BV::kSize**2) bits.
// The implementation is optimized for better performance on
// sparse bit vectors, i.e. the those with few set bits.
template <usize kLevel1Size = 1, class BV = BasicBitVector<> >
class TwoLevelBitVector {
  // This is essentially a 2-level bit vector.
  // Set bit in the first level BV indicates that there are set bits
  // in the corresponding BV of the second level.
  // This structure allows O(kLevel1Size) time for clear() and empty(),
  // as well fast handling of sparse BVs.
 public:
  enum SizeEnum : usize { kSize = BV::kSize * BV::kSize * kLevel1Size };
  // No CTOR.

  usize size() const { return kSize; }

  void clear() {
    for (usize i = 0; i < kLevel1Size; i++)
      l1_[i].clear();
  }

  void setAll() {
    for (usize i0 = 0; i0 < kLevel1Size; i0++) {
      l1_[i0].setAll();
      for (usize i1 = 0; i1 < BV::kSize; i1++)
        l2_[i0][i1].setAll();
    }
  }

  bool empty() const {
    for (usize i = 0; i < kLevel1Size; i++)
      if (!l1_[i].empty())
        return false;
    return true;
  }

  // Returns true if the bit has changed from 0 to 1.
  bool setBit(usize idx) {
    check(idx);
    usize i0 = idx0(idx);
    usize i1 = idx1(idx);
    usize i2 = idx2(idx);
    if (!l1_[i0].getBit(i1)) {
      l1_[i0].setBit(i1);
      l2_[i0][i1].clear();
    }
    bool res = l2_[i0][i1].setBit(i2);
    // Printf("%s: %zd => %zd %zd %zd; %d\n", __func__,
    // idx, i0, i1, i2, res);
    return res;
  }

  bool clearBit(usize idx) {
    check(idx);
    usize i0 = idx0(idx);
    usize i1 = idx1(idx);
    usize i2 = idx2(idx);
    bool res = false;
    if (l1_[i0].getBit(i1)) {
      res = l2_[i0][i1].clearBit(i2);
      if (l2_[i0][i1].empty())
        l1_[i0].clearBit(i1);
    }
    return res;
  }

  bool getBit(usize idx) const {
    check(idx);
    usize i0 = idx0(idx);
    usize i1 = idx1(idx);
    usize i2 = idx2(idx);
    // Printf("%s: %zd => %zd %zd %zd\n", __func__, idx, i0, i1, i2);
    return l1_[i0].getBit(i1) && l2_[i0][i1].getBit(i2);
  }

  usize getAndClearFirstOne() {
    for (usize i0 = 0; i0 < kLevel1Size; i0++) {
      if (l1_[i0].empty()) continue;
      usize i1 = l1_[i0].getAndClearFirstOne();
      usize i2 = l2_[i0][i1].getAndClearFirstOne();
      if (!l2_[i0][i1].empty())
        l1_[i0].setBit(i1);
      usize res = i0 * BV::kSize * BV::kSize + i1 * BV::kSize + i2;
      // Printf("getAndClearFirstOne: %zd %zd %zd => %zd\n", i0, i1, i2, res);
      return res;
    }
    CHECK(0);
    return 0;
  }

  // Do "this |= v" and return whether new bits have been added.
  bool setUnion(const TwoLevelBitVector &v) {
    bool res = false;
    for (usize i0 = 0; i0 < kLevel1Size; i0++) {
      BV t = v.l1_[i0];
      while (!t.empty()) {
        usize i1 = t.getAndClearFirstOne();
        if (l1_[i0].setBit(i1))
          l2_[i0][i1].clear();
        if (l2_[i0][i1].setUnion(v.l2_[i0][i1]))
          res = true;
      }
    }
    return res;
  }

  // Do "this &= v" and return whether any bits have been removed.
  bool setIntersection(const TwoLevelBitVector &v) {
    bool res = false;
    for (usize i0 = 0; i0 < kLevel1Size; i0++) {
      if (l1_[i0].setIntersection(v.l1_[i0]))
        res = true;
      if (!l1_[i0].empty()) {
        BV t = l1_[i0];
        while (!t.empty()) {
          usize i1 = t.getAndClearFirstOne();
          if (l2_[i0][i1].setIntersection(v.l2_[i0][i1]))
            res = true;
          if (l2_[i0][i1].empty())
            l1_[i0].clearBit(i1);
        }
      }
    }
    return res;
  }

  // Do "this &= ~v" and return whether any bits have been removed.
  bool setDifference(const TwoLevelBitVector &v) {
    bool res = false;
    for (usize i0 = 0; i0 < kLevel1Size; i0++) {
      BV t = l1_[i0];
      t.setIntersection(v.l1_[i0]);
      while (!t.empty()) {
        usize i1 = t.getAndClearFirstOne();
        if (l2_[i0][i1].setDifference(v.l2_[i0][i1]))
          res = true;
        if (l2_[i0][i1].empty())
          l1_[i0].clearBit(i1);
      }
    }
    return res;
  }

  void copyFrom(const TwoLevelBitVector &v) {
    clear();
    setUnion(v);
  }

  // Returns true if 'this' intersects with 'v'.
  bool intersectsWith(const TwoLevelBitVector &v) const {
    for (usize i0 = 0; i0 < kLevel1Size; i0++) {
      BV t = l1_[i0];
      t.setIntersection(v.l1_[i0]);
      while (!t.empty()) {
        usize i1 = t.getAndClearFirstOne();
        if (!v.l1_[i0].getBit(i1)) continue;
        if (l2_[i0][i1].intersectsWith(v.l2_[i0][i1]))
          return true;
      }
    }
    return false;
  }

  // for (TwoLevelBitVector<>::Iterator it(bv); it.hasNext();) {
  //   usize idx = it.next();
  //   use(idx);
  // }
  class Iterator {
   public:
    Iterator() { }
    explicit Iterator(const TwoLevelBitVector &bv) : bv_(bv), i0_(0), i1_(0) {
      it1_.clear();
      it2_.clear();
    }

    bool hasNext() const {
      if (it1_.hasNext()) return true;
      for (usize i = i0_; i < kLevel1Size; i++)
        if (!bv_.l1_[i].empty()) return true;
      return false;
    }

    usize next() {
      // Printf("++++: %zd %zd; %d %d; size %zd\n", i0_, i1_, it1_.hasNext(),
      //       it2_.hasNext(), kSize);
      if (!it1_.hasNext() && !it2_.hasNext()) {
        for (; i0_ < kLevel1Size; i0_++) {
          if (bv_.l1_[i0_].empty()) continue;
          it1_ = typename BV::Iterator(bv_.l1_[i0_]);
          // Printf("+i0: %zd %zd; %d %d; size %zd\n", i0_, i1_, it1_.hasNext(),
          //   it2_.hasNext(), kSize);
          break;
        }
      }
      if (!it2_.hasNext()) {
        CHECK(it1_.hasNext());
        i1_ = it1_.next();
        it2_ = typename BV::Iterator(bv_.l2_[i0_][i1_]);
        // Printf("++i1: %zd %zd; %d %d; size %zd\n", i0_, i1_, it1_.hasNext(),
        //       it2_.hasNext(), kSize);
      }
      CHECK(it2_.hasNext());
      usize i2 = it2_.next();
      usize res = i0_ * BV::kSize * BV::kSize + i1_ * BV::kSize + i2;
      // Printf("+ret: %zd %zd; %d %d; size %zd; res: %zd\n", i0_, i1_,
      //       it1_.hasNext(), it2_.hasNext(), kSize, res);
      if (!it1_.hasNext() && !it2_.hasNext())
        i0_++;
      return res;
    }

   private:
    const TwoLevelBitVector &bv_;
    usize i0_, i1_;
    typename BV::Iterator it1_, it2_;
  };

 private:
  void check(usize idx) const { CHECK_LE(idx, size()); }

  usize idx0(usize idx) const {
    usize res = idx / (BV::kSize * BV::kSize);
    CHECK_LE(res, kLevel1Size);
    return res;
  }

  usize idx1(usize idx) const {
    usize res = (idx / BV::kSize) % BV::kSize;
    CHECK_LE(res, BV::kSize);
    return res;
  }

  usize idx2(usize idx) const {
    usize res = idx % BV::kSize;
    CHECK_LE(res, BV::kSize);
    return res;
  }

  BV l1_[kLevel1Size];
  BV l2_[kLevel1Size][BV::kSize];
};

} // namespace __sanitizer

#endif // SANITIZER_BITVECTOR_H
