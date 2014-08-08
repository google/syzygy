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
#include "syzygy/core/address.h"

#include <iostream>
#include "base/strings/stringprintf.h"

namespace core {

// Host function for compile asserts.
void CompileAsserts() {
  COMPILE_ASSERT(sizeof(RelativeAddress) == sizeof(uint32),
                 relative_address_must_be_4_byte);
  COMPILE_ASSERT(sizeof(AbsoluteAddress) == sizeof(uint32),
                 absolute_address_must_be_4_byte);
  COMPILE_ASSERT(sizeof(FileOffsetAddress) == sizeof(uint32),
                 file_offset_must_be_4_byte);
}

const RelativeAddress RelativeAddress::kInvalidAddress(~0U);
const AbsoluteAddress AbsoluteAddress::kInvalidAddress(~0U);
const FileOffsetAddress FileOffsetAddress::kInvalidAddress(~0U);

std::ostream& operator<<(std::ostream& str, RelativeAddress addr) {
  str << base::StringPrintf("Relative(0x%08X)", addr.value());
  return str;
}

std::ostream& operator<<(std::ostream& str, AbsoluteAddress addr) {
  str << base::StringPrintf("Absolute(0x%08X)", addr.value());
  return str;
}

std::ostream& operator<<(std::ostream& str, FileOffsetAddress addr) {
  str << base::StringPrintf("FileOffset(0x%08X)", addr.value());
  return str;
}

}  // namespace core
