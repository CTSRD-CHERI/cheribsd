//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef _LIBCPP___BIT_ROTATE_H
#define _LIBCPP___BIT_ROTATE_H

#include <__concepts/arithmetic.h>
#include <__config>
#include <__type_traits/is_unsigned_integer.h>
#include <limits>

#if !defined(_LIBCPP_HAS_NO_PRAGMA_SYSTEM_HEADER)
#  pragma GCC system_header
#endif

_LIBCPP_BEGIN_NAMESPACE_STD

template<class _Tp>
_LIBCPP_HIDE_FROM_ABI _LIBCPP_CONSTEXPR_SINCE_CXX14
_Tp __rotr(_Tp __t, unsigned int __cnt) _NOEXCEPT
{
    static_assert(__libcpp_is_unsigned_integer<_Tp>::value, "__rotr requires an unsigned integer type");
    const unsigned int __dig = numeric_limits<_Tp>::digits;
    if ((__cnt % __dig) == 0)
        return __t;
    return (__t >> (__cnt % __dig)) | (__t << (__dig - (__cnt % __dig)));
}

#if __has_feature(capabilities)
template<>
_LIBCPP_HIDE_FROM_ABI _LIBCPP_CONSTEXPR_SINCE_CXX14 inline
unsigned __intcap __rotr(unsigned __intcap __t, unsigned int __cnt) _NOEXCEPT {
    // __builtin_cheri_address_set cannot be used in a constant expression (yet), so we return a null-derived integer.
    return std::__rotr(static_cast<ptraddr_t>(__t), __cnt);
}
#endif

#if _LIBCPP_STD_VER >= 20

template <__libcpp_unsigned_integer _Tp>
[[nodiscard]] _LIBCPP_HIDE_FROM_ABI constexpr _Tp rotl(_Tp __t, unsigned int __cnt) noexcept {
  const unsigned int __dig = numeric_limits<_Tp>::digits;
  if ((__cnt % __dig) == 0)
    return __t;
  return (__t << (__cnt % __dig)) | (__t >> (__dig - (__cnt % __dig)));
}

#if __has_feature(capabilities)
template<>
_LIBCPP_HIDE_FROM_ABI constexpr inline unsigned __intcap rotl(unsigned __intcap __t, unsigned int __cnt) noexcept {
    // __builtin_cheri_address_set cannot be used in a constant expression (yet), so we return a null-derived integer.
    return std::rotl(static_cast<ptraddr_t>(__t), __cnt);
}
#endif

template <__libcpp_unsigned_integer _Tp>
[[nodiscard]] _LIBCPP_HIDE_FROM_ABI constexpr _Tp rotr(_Tp __t, unsigned int __cnt) noexcept {
  return std::__rotr(__t, __cnt);
}

#endif // _LIBCPP_STD_VER >= 20

_LIBCPP_END_NAMESPACE_STD

#endif // _LIBCPP___BIT_ROTATE_H
