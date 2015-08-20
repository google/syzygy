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

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"

namespace bard {

// A simple class for wrapping function arguments of different sizes and safely
// retrieving them in the desired type.
class RawArgumentConverter {
 public:
  // Initializes a new raw argument.
  // @param arg_data a pointer to the argument to be saved.
  // @param arg_size the size in bytes of the argument.
  RawArgumentConverter(const void* const arg_data, const uint32_t arg_size);

  // Retrieve this argument in the desired type.
  // @tparam T The type that this argument should to be retrieved as.
  // @returns the argument converted to type @tp T.
  template <typename T>
  T RetrieveAs() const;

 private:
  scoped_ptr<uint8_t> arg_;
  uint32_t arg_size_;

  DISALLOW_COPY_AND_ASSIGN(RawArgumentConverter);
};

template <typename T>
T RawArgumentConverter::RetrieveAs() const {
  DCHECK_EQ(sizeof(T), arg_size_);
  DCHECK_NE(static_cast<uint8_t*>(nullptr), arg_.get());
  T result;
  ::memcpy(&result, arg_.get(), arg_size_);
  return result;
}

}  // namespace bard

#endif  // SYZYGY_BARD_RAW_ARGUMENT_CONVERTER_H_
