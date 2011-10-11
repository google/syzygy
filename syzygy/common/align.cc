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

#include "syzygy/common/align.h"

#include "base/logging.h"

namespace common {

bool IsPowerOfTwo(size_t value) {
  return value != 0 && (value & (value - 1)) == 0;
}

size_t AlignUp(size_t value, size_t alignment) {
  DCHECK(alignment != 0);

  if (IsPowerOfTwo(alignment)) {
    return (value + alignment - 1) & ~(alignment - 1);
  } else {
    return ((value + alignment - 1) / alignment) * alignment;
  }
}

size_t AlignDown(size_t value, size_t alignment) {
  DCHECK(alignment != 0);

  if (IsPowerOfTwo(alignment)) {
    return value & ~(alignment - 1);
  } else {
    return (value / alignment) * alignment;
  }
}

bool IsAligned(size_t value, size_t alignment) {
  return AlignDown(value, alignment) == value;
}

}  // namespace common
