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
// Note: not thread safe!
template<typename T, size_t InlineSize>
class SimpleSmallVector {
protected:
	T* buffer;
	unsigned count = 0;
	unsigned alloc = InlineSize;
	// TODO: use a union to save space?
	T inline_array[InlineSize];

	bool is_inline() const { return alloc == InlineSize; }

	void grow() {
		// TODO: what is a sensible growth strategy here
		constexpr size_t grow_by = 16;
		size_t new_size = (alloc + grow_by) * sizeof(T);
		T* old_buffer = buffer;
		if (is_inline()) {
			dbg("SimpleSmallVector::grow(): moving from inline"
			    "storage to heap allocated");
			// Assume this gives enough alignment
			buffer = static_cast<T*>(xmalloc(new_size));
			__builtin_memcpy(buffer, old_buffer, count * sizeof(T));
		} else {
			buffer = static_cast<T*>(realloc(old_buffer, new_size));
			dbg_assert(buffer != nullptr);
		}
		dbg("SimpleSmallVector::grow(): Old buffer: %#p, new buffer: "
		    "%#p, end(): %#p", old_buffer, buffer, end());
		alloc += grow_by;
	}
public:
	SimpleSmallVector() {
		static_assert(__is_trivially_copyable(T), "Only POD types allowed!");
		buffer = inline_array;
	}
	~SimpleSmallVector() {

	}
	[[nodiscard]] size_t size() const { return count; }
	[[nodiscard]] size_t capacity() const { return alloc; }
	[[nodiscard]] bool empty() const { return count; }
	[[nodiscard]] const T* begin() const { return buffer; }
	[[nodiscard]] const T* end() const { return buffer + size(); }


	template <typename... ArgTypes> T* add(ArgTypes &&... Args) {
		if (__predict_false(size() >= capacity())) {
			grow();
			dbg("SimpleSmallVector::end() after grow: %#p, sizeof(T)=%zd, remaining=%zd",
			     end(), sizeof(T), (size_t)cheri_bytes_remaining(end()));
		}
		dbg_assert(size() < capacity());
		dbg_assert(cheri_bytes_remaining(end()) >= sizeof(T));
		T* result = ::new ((void *)end()) T(std::forward<ArgTypes>(Args)...);
		count++;
		return result;
	}
};
