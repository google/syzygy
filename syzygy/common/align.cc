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

#include "syzygy/common/align.h"

#include "base/logging.h"

namespace common {

namespace {

template <typename T>
uint8 CountTrailingZeros(T value) {
  uint8 trailing_zeros = 0;

  // Sets the trailing zeros to one and sets the other bits to zero.
  // This is inspired from the code on this page:
  // http://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightLinear
  value = (value ^ (value - 1)) >> 1;

  for (; value > 0; trailing_zeros++)
    value >>= 1;

  return trailing_zeros;
}

}  // namespace

bool IsPowerOfTwo(size_t value) {
  return value != 0 && (value & (value - 1)) == 0;
}

size_t AlignUp(size_t value, size_t alignment) {
  DCHECK_NE(0U, alignment);

  if (IsPowerOfTwo(alignment)) {
    return (value + alignment - 1) & ~(alignment - 1);
  } else {
    return ((value + alignment - 1) / alignment) * alignment;
  }
}

size_t AlignDown(size_t value, size_t alignment) {
  DCHECK_NE(0U, alignment);

  if (IsPowerOfTwo(alignment)) {
    return value & ~(alignment - 1);
  } else {
    return (value / alignment) * alignment;
  }
}

bool IsAligned(size_t value, size_t alignment) {
  return AlignDown(value, alignment) == value;
}

size_t GetAlignment(size_t value) {
  return 1 << CountTrailingZeros(value);
}

bool IsPowerOfTwo64(uint64 value) {
  return value != 0 && (value & (value - 1)) == 0;
}

uint64 AlignUp64(uint64 value, uint64 alignment) {
  DCHECK_NE(0U, alignment);

  if (IsPowerOfTwo64(alignment)) {
    return (value + alignment - 1) & ~(alignment - 1);
  } else {
    return ((value + alignment - 1) / alignment) * alignment;
  }
}

uint64 AlignDown64(uint64 value, uint64 alignment) {
  DCHECK_NE(0U, alignment);

  if (IsPowerOfTwo64(alignment)) {
    return value & ~(alignment - 1);
  } else {
    return (value / alignment) * alignment;
  }
}

bool IsAligned64(uint64 value, uint64 alignment) {
  return AlignDown64(value, alignment) == value;
}

uint64 GetAlignment64(uint64 value) {
  return 1ULL << CountTrailingZeros(value);
}

}  // namespace common
