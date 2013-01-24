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
struct RangePairLess {
  typedef std::pair<SourceRangeType, DestinationRangeType> RangePair;

  bool operator()(const RangePair& ranges1, const RangePair& ranges2) const {
    if (ranges1.first.Intersects(ranges2.first))
      return false;
    return ranges1.first < ranges2.first;
  }
};

// A utility function for doing a comparison between two address ranges. This
// comparison endows them a with a complete ordering.
template <typename AddressRangeType>
struct CompleteAddressRangeLess {
  bool operator()(const AddressRangeType& range1,
                  const AddressRangeType& range2) {
    if (range1.start() < range2.start())
      return true;
    if (range2.start() < range1.start())
      return false;
    return range1.size() < range2.size();
  }
};

// A utility function for comparing a pair of AddressRange objects using the
// full ordering compare function.
template <typename FirstAddressRange, typename SecondAddressRange>
struct CompleteAddressRangePairLess {
  bool operator()(
      const std::pair<FirstAddressRange, SecondAddressRange>& pair1,
      const std::pair<FirstAddressRange, SecondAddressRange>& pair2) {
    if (CompleteAddressRangeLess<FirstAddressRange>()(pair1.first, pair2.first))
      return true;
    if (CompleteAddressRangeLess<FirstAddressRange>()(pair2.first, pair1.first))
      return false;
    return CompleteAddressRangeLess<SecondAddressRange>()(pair1.second,
                                                          pair2.second);
  }
};

}  // namespace internal

}  // namespace core

#endif  // SYZYGY_CORE_ADDRESS_SPACE_INTERNAL_H_
