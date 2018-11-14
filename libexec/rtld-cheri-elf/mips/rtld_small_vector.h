/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <cstddef>
#include <utility> // std::forward
#include "rtld.h"

// A simple version of e.g. llvm::SmallVector
// This does not support shrinking, only growing and only POD types
template<typename T, size_t InlineSize>
class SimpleSmallVector {
protected:
	T* buffer;
	unsigned count = 0;
	unsigned alloc = InlineSize;
	// TODO: use a union to save space?
	T inline_array[InlineSize];
	void grow() {
		rtld_fatal("GROWING VECTOR NOT IMPLEMENTED!");
	}
public:
	SimpleSmallVector() {
		static_assert(__is_trivially_copyable(T), "Only POD types allowed!");
		buffer = &inline_array[0];
	}
	size_t size() const { return count; }
	size_t capacity() const { return alloc; }
	[[nodiscard]] bool empty() const { return count; }
	const T* begin() const { return buffer; }
	const T* end() const { return buffer + size(); }


	template <typename... ArgTypes> T* add(ArgTypes &&... Args) {
		if (__predict_false(size() >= this->capacity()))
			grow();
		T* result = ::new ((void *)this->end()) T(std::forward<ArgTypes>(Args)...);
		count++;
		return result;
	}
};
