// Copyright 2013 Google Inc. All Rights Reserved.
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
// Declares AddressFilter which maintains a disjoint collection of marked
// regions in a contiguous address space.

#ifndef SYZYGY_CORE_ADDRESS_FILTER_H_
#define SYZYGY_CORE_ADDRESS_FILTER_H_

#include "syzygy/core/address_space.h"

namespace core {

template<typename AddressType, typename SizeType>
struct AddressRangeLessThan;

template<typename AddressType, typename SizeType>
class AddressFilter {
 public:
  typedef AddressRange<AddressType, SizeType> Range;
  typedef AddressRangeLessThan<AddressType, SizeType> RangeLessThan;
  typedef std::set<Range, RangeLessThan> RangeSet;

  // Constructor. Builds an empty address filter over the given address bounds.
  // @param extent The address-space over which this filter is defined.
  explicit AddressFilter(const Range& extent) : extent_(extent) {
  }

  // Marks the given address range.
  // @param range The range to mark.
  void Mark(const Range& range);

  // Unmarks the given address range.
  // @param range The range to unmark.
  void Unmark(const Range& range);

  // Determines if the given address range is marked in its entirety.
  // @param range The address range to check.
  // @returns false if any locations in the range are not marked, or true if
  //     they all are.
  bool IsMarked(const Range& range) const;

  // Determines if the given address range is not marked at all.
  // @param range The address range to check.
  // @returns false if any locations in the range are marked, or true if
  //     they are all unmarked.
  bool IsUnmarked(const Range& range) const;

  // @name Accessors.
  // @{
  const RangeSet& marked_ranges() const { return marked_ranges_; }
  size_t size() const { return marked_ranges_.size(); }
  // @}

 protected:
  // The extents of this filter.
  Range extent_;

  // The set of disjoint marked ranges.
  RangeSet marked_ranges_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AddressFilter);
};

}  // namespace core

// Bring in the implementation.
#include "syzygy/core/address_filter_impl.h"

#endif  // SYZYGY_CORE_ADDRESS_FILTER_H_
