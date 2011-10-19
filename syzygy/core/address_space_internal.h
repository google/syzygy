// Copyright 2010 Google Inc.
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
// This file contains internals for the AddressRange, AddressSpace and
// AddressRangeMap implementations. It is not meant to be included directly.

#ifndef SYZYGY_CORE_ADDRESS_SPACE_INTERNAL_H_
#define SYZYGY_CORE_ADDRESS_SPACE_INTERNAL_H_

#include <utility>

namespace core {

namespace internal {

// A comparison functor for std::pair<AddressRange, AddressRange> that is used
// by the AddressRangeMap.
template<typename SourceRangeType, typename DestinationRangeType>
struct RangePairCompare {
  typedef std::pair<SourceRangeType, DestinationRangeType> RangePair;

  bool operator()(const RangePair& ranges1, const RangePair& ranges2) const {
    if (ranges1.first.Intersects(ranges2.first))
      return false;
    return ranges1.first < ranges2.first;
  }
};

}  // namespace internal

}  // namespace core

#endif  // SYZYGY_CORE_ADDRESS_SPACE_INTERNAL_H_
