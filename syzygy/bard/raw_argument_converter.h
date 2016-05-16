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
//
// Declares RawArgumentConverter, a utility class for wrapping up generic
// function arguments of different sizes and retrieving them in the necessary
// types.
#ifndef SYZYGY_BARD_RAW_ARGUMENT_CONVERTER_H_
#define SYZYGY_BARD_RAW_ARGUMENT_CONVERTER_H_

#include <stdint.h>
#include <memory>

#include "base/logging.h"

namespace bard {

// A simple class for wrapping function arguments of different sizes and safely
// retrieving them in the desired type.
class RawArgumentConverter {
 public:
  // Initializes a new raw argument.
  // @param arg_data a pointer to the argument to be saved.
  // @param arg_size the size in bytes of the argument.
  RawArgumentConverter(const void* const arg_data, const uint32_t arg_size);

  // Explicitly allow copy and assign for use with STL containers.
  RawArgumentConverter(const RawArgumentConverter&) = default;
  RawArgumentConverter& operator=(const RawArgumentConverter&) = default;

  // Retrieve this argument in the desired type.
  // @tparam Type The type that this argument should to be retrieved as.
  // @param value The value to be populated.
  // @returns true on success, false otherwise.
  template <typename Type>
  bool RetrieveAs(Type* value) const;

 private:
  static const size_t kMaxArgSize = 8;
  uint8_t arg_[kMaxArgSize];
  uint32_t arg_size_;
};

template <typename Type>
bool RawArgumentConverter::RetrieveAs(Type* value) const {
  DCHECK_NE(static_cast<Type*>(nullptr), value);
  if (sizeof(Type) != arg_size_)
    return false;
  ::memcpy(value, arg_, arg_size_);
  return true;
}

}  // namespace bard

#endif  // SYZYGY_BARD_RAW_ARGUMENT_CONVERTER_H_
