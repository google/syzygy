// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/bard/raw_argument_converter.h"

#include <string.h>

namespace bard {

RawArgumentConverter::RawArgumentConverter(const void* const arg_data,
                                           const uint32_t arg_size) {
  DCHECK_NE(static_cast<void*>(nullptr), arg_data);
  arg_size_ = arg_size;
  DCHECK_GE(kMaxArgSize, arg_size);
  ::memcpy(arg_, arg_data, arg_size_);
}

}  // namespace bard
