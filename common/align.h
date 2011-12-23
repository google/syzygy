// Copyright 2011 Google Inc.
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

namespace common {

// @returns true iff @p value is a power of two.
bool IsPowerOfTwo(size_t value);

// @param value the value to round up.
// @param alignment the alignment boundary to round @p value up to.
// @pre alignment != 0.
// @returns @p value rounded up to the nearest higher multiple of @p alignment.
size_t AlignUp(size_t value, size_t alignment);

// @param value the value to round up.
// @param alignment the alignment boundary to round @p value up to.
// @pre alignment != 0.
// @returns @p value rounded down to the nearest lower multiple of @p alignment.
size_t AlignDown(size_t value, size_t alignment);

// @param value the value to test.
// @param alignment the alignment boundary to test.
// @pre alignment != 0.
// @returns true iff value is an even multiple of alignment.
bool IsAligned(size_t value, size_t alignment);

}  // namespace common

#endif  // SYZYGY_COMMON_ALIGN_H_
