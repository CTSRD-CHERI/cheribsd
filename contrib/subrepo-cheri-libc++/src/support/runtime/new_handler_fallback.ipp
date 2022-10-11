// -*- C++ -*-
//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

namespace std {

_LIBCPP_SAFE_STATIC static _Atomic(std::new_handler) __new_handler;

new_handler
set_new_handler(new_handler handler) noexcept
{
    return __c11_atomic_exchange(&__new_handler, handler, __ATOMIC_SEQ_CST);
}

new_handler
get_new_handler() noexcept
{
    return __c11_atomic_load(&__new_handler, __ATOMIC_SEQ_CST);
}

} // namespace std
