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

#include "syzygy/core/address_range.h"

namespace core {

template<typename AddressType, typename SizeType>
struct AddressRangeLessThan;

template<typename AddressType, typename SizeType>
class AddressFilter {
 public:
  typedef AddressType Address;
  typedef SizeType Size;
  typedef AddressRange<AddressType, SizeType> Range;
  typedef AddressRangeLessThan<AddressType, SizeType> RangeLessThan;
  typedef std::set<Range, RangeLessThan> RangeSet;

  // Default constructor. This is only for compatibility with STL containers.
  AddressFilter() { }

  // Constructor. Builds an empty address filter over the given address bounds.
  // @param extent The address-space over which this filter is defined.
  explicit AddressFilter(const Range& extent) : extent_(extent) {
  }

  // Copy constructor. We explicitly want to support set operations on these, so
  // expose the copy constructor facilitates this.
  // @param rhs The AddressFilter to copy.
  AddressFilter(const AddressFilter& rhs)
      : extent_(rhs.extent_), marked_ranges_(rhs.marked_ranges_) {
  }

  // Assignment operator. We explicitly want to support arithmetic-like set
  // operations so expose an assignment operator.
  // @param rhs The AddressFilter to copy.
  // @returns a reference to this AddressFilter.
  AddressFilter& operator=(const AddressFilter& rhs) {
    extent_ = rhs.extent_;
    marked_ranges_ = rhs.marked_ranges_;
    return *this;
  }

  // Clears this AddressFilter.
  void Clear() { marked_ranges_.clear(); }

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
  const Range& extent() const { return extent_; }
  const RangeSet& marked_ranges() const { return marked_ranges_; }
  size_t size() const { return marked_ranges_.size(); }
  bool empty() const { return marked_ranges_.empty(); }
  // @}

  // @name Comparison operators.
  // @{
  bool operator==(const AddressFilter& rhs) const {
    return extent_ == rhs.extent_ && marked_ranges_ == rhs.marked_ranges_;
  }
  bool operator!=(const AddressFilter& rhs) const { return !operator==(rhs); }
  // @}

  // @name Set operations.
  // @{
  // Inverts this AddressFilter.
  // @param filter The address filter to populate with the inverse. This may
  //     be |this|, allowing the operation to be done in place.
  void Invert(AddressFilter* filter) const;

  // Calculates the intersection of this address filter and another.
  // @param other The filter to intersect with.
  // @param filter The filter to populate with the intersection. This may
  //     be |this|, allowing the operation to be done in place.
  // @note The returned filter will have the same extent as this filter.
  void Intersect(const AddressFilter& other, AddressFilter* filter) const;

  // Calculates the union of this address filter and another.
  // @param other The filter with which to calculate the union.
  // @param filter The filter to populate with the union. This may
  //     be |this|, allowing the operation to be done in place.
  // @note The returned filter will have the same extent as this filter.
  void Union(const AddressFilter& other, AddressFilter* filter) const;

  // Calculates the difference between this set and another.
  // @param other The filter to be subtracted from this filter.
  // @param filter The filter to populate with the difference. This may
  //     be |this|, allowing the operation to be done in place.
  // @note The returned filter will have the same extent as this filter.
  void Subtract(const AddressFilter& other, AddressFilter* filter) const;
  // @}

 protected:
  // The extents of this filter.
  Range extent_;

  // The set of disjoint marked ranges.
  RangeSet marked_ranges_;
};

}  // namespace core

// Bring in the implementation.
#include "syzygy/core/address_filter_impl.h"

#endif  // SYZYGY_CORE_ADDRESS_FILTER_H_
