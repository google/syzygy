// Copyright 2011 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Utility functions to align and test alignment.

#ifndef SYZYGY_COMMON_ALIGN_H_
#define SYZYGY_COMMON_ALIGN_H_

#include "base/basictypes.h"

namespace common {

// @tparam T Any type.
// @param value The value to test.
// @param pointer The pointer to test.
// @returns true iff @p value or @p pointer is a (positive) power of two.
bool IsPowerOfTwo(size_t value);
template<typename T> bool IsPowerOfTwo(const T* pointer);

// @tparam T Any type.
// @param value The value to round up.
// @param pointer The pointer to round up.
// @param alignment the alignment boundary to round @p value up to.
// @pre alignment != 0.
// @returns @p value or @p pointer rounded up to the nearest higher multiple of
//     @p alignment.
size_t AlignUp(size_t value, size_t alignment);
template<typename T> T* AlignUp(T* pointer, size_t alignment);
template<typename T> const T* AlignUp(const T* pointer, size_t alignment);

// @tparam T Any type.
// @param value The value to round up.
// @param pointer The pointer to round down.
// @param alignment The alignment boundary to round @p value up to.
// @pre alignment != 0.
// @returns @p value or @p pointer rounded down to the nearest lower multiple of
//     @p alignment.
size_t AlignDown(size_t value, size_t alignment);
template<typename T> T* AlignDown(T* pointer, size_t alignment);
template<typename T> const T* AlignDown(const T* pointer, size_t alignment);

// @tparam T Any type.
// @param value The value to test.
// @param pointer The pointer to test.
// @param alignment The alignment boundary to test.
// @pre alignment != 0.
// @returns true iff value is an even multiple of alignment.
bool IsAligned(size_t value, size_t alignment);
template<typename T> bool IsAligned(const T* pointer, size_t alignment);

// Determines the address alignment. If @p value or @p pointer is 0, the
// maximum alignment for a 32-bit value is returned (0x80000000).
// @tparam T Any type.
// @param value The value for which to get the alignment.
// @param pointer The pointer for which to get the alignment.
// @returns the power of 2 on which @p value or @p pointer is aligned.
size_t GetAlignment(size_t value);
template<typename T> size_t GetAlignment(const T* pointer);

// @tparam T Any type.
// @param value An integer value to test.
// @param pointer The pointer to test.
// @returns true iff @p value  or @p value is a power of two.
bool IsPowerOfTwo64(uint64 value);

// @param value the value to round up.
// @param alignment the alignment boundary to round @p value up to.
// @pre alignment != 0.
// @returns @p value rounded up to the nearest higher multiple of @p alignment.
uint64 AlignUp64(uint64 value, uint64 alignment);

// @param value the value to round up.
// @param alignment the alignment boundary to round @p value up to.
// @pre alignment != 0.
// @returns @p value rounded down to the nearest lower multiple of @p alignment.
uint64 AlignDown64(uint64 value, uint64 alignment);

// @param value the value to test.
// @param alignment the alignment boundary to test.
// @pre alignment != 0.
// @returns true iff value is an even multiple of alignment.
bool IsAligned64(uint64 value, uint64 alignment);

// Determines the address alignment. If @p value or @p pointer is 0, the
// maximum alignment for a 64-bit value is returned (1 << 63).
// @param value The value for which to get the alignment.
// @returns the power of 2 on which @p value is aligned.
uint64 GetAlignment64(uint64 value);

}  // namespace common

// Brings in the implementations of the templated functions.
#include "syzygy/common/align_impl.h"

#endif  // SYZYGY_COMMON_ALIGN_H_
