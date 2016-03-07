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

#ifndef SYZYGY_COMMON_BUFFER_PARSER_IMPL_H_
#define SYZYGY_COMMON_BUFFER_PARSER_IMPL_H_

#ifndef SYZYGY_COMMON_BUFFER_PARSER_H_
#error This file is only meant to be included from buffer_parser.h.
#endif

#include <stddef.h>

#include "syzygy/common/align.h"

namespace common {

namespace detail {

// Utility template class for determining the alignment of a given type.
template <typename DataType>
struct GetAlignment {
  struct Helper {
    uint8_t foo;
    DataType bar;
  };
  static const size_t kAlignment = offsetof(Helper, bar);
};

}  // namespace detail

template <class DataType>
bool BinaryBufferParser::GetAtImplicitAlignment(
    size_t pos, size_t size, const DataType** data_ptr) const {
  const size_t kAlign = detail::GetAlignment<DataType>::kAlignment;
  return GetAtExplicitAlignment(pos, size, kAlign, data_ptr);
}

template <class DataType>
bool BinaryBufferParser::GetAtExplicitAlignment(
    size_t pos, size_t size, size_t align, const DataType** data_ptr) const {
  if (!common::IsAligned(data_ + pos, align))
    return false;
  return GetAt(pos, size, reinterpret_cast<const void**>(data_ptr));
}

}  // namespace common

#endif  // SYZYGY_COMMON_BUFFER_PARSER_IMPL_H_
