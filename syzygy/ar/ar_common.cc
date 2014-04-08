// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/ar/ar_common.h"

namespace ar {

const size_t kArFileAlignment = 2;
const char kArGlobalMagic[8] = { '!', '<', 'a', 'r', 'c', 'h', '>', '\n' };
const char kArFileMagic[2] = { 0x60, 0x0A };

// Swaps endianness.
uint32 SwapEndianness(uint32 value) {
  return (value & 0x000000FF) << 24 |
         (value & 0x0000FF00) << 8 |
         (value & 0x00FF0000) >> 8 |
         (value & 0xFF000000) >> 24;
}

}  // namespace ar
