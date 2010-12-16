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
#ifndef SAWBUCK_IMAGE_UTIL_ADDRESS_SPACE_H_
#define SAWBUCK_IMAGE_UTIL_ADDRESS_SPACE_H_

#include "base/logging.h"
#include <map>

namespace image_util {

// Forward declaration.
template <typename AddressType, typename SizeType> class AddressRange;

// An address space is a mapping from a set of non-overlapping address ranges
// (AddressSpace::Range), each of non-zero size, to an ItemType.
template <typename AddressType, typename SizeType, typename ItemType>
class AddressSpace {
 public:
  typedef AddressRange<AddressType, SizeType> Range;
  typedef std::map<Range, ItemType> RangeMap;

  // Create an empy address space.
  AddressSpace();

  // Insert @p range mapping to @p item unless @p range intersects
  // an existing range.
  // @param range the range to insert.
  // @param item the item to associate with @p range.
  // @param it on success, returns an iterator to the inserted item.
  // @returns true iff @p range inserted.
  bool Insert(const Range& range,
              const ItemType& item,
              typename RangeMap::iterator* it = NULL);

  // Remove the range that exactly matches @p range.
  // Returns true iff @p range is removed.
  bool Remove(const Range& range);

  const RangeMap& ranges() const { return ranges_; }

  // Finds the first contained range that intersects @p range.
  typename RangeMap::const_iterator FindFirstIntersection(
      const Range& range) const;
  typename RangeMap::iterator FindFirstIntersection(
      const Range& range);

  // Finds the range that contains @p range.
  typename RangeMap::const_iterator FindContaining(const Range& range) const;
  typename RangeMap::iterator FindContaining(const Range& range);

 private:
  // Our ranges and their associated items.
  RangeMap ranges_;
};

// An address range has a start address and a size.
// Both types must provide operator <, and it must be possible to
// add a SizeType to an AddressType.
template <typename AddressType, typename SizeType>
class AddressRange {
 public:
  AddressRange() : start_(0), size_(0) {
  }

  AddressRange(const AddressType &start, const SizeType& size)
      : start_(start), size_(size) {
    DCHECK(size_ > 0);
  }

  AddressRange(const AddressRange &other)
      : start_(other.start_), size_(other.size_) {
    DCHECK(size_ > 0);
  }

  void operator=(const AddressRange &other) {
    start_ = other.start_;
    size_ = other.size_;
  }

  // Returns true iff @p other is contained within this range.
  bool Contains(const AddressRange& other) const {
    if (other.start_ < start_ ||
        other.start_ + other.size_ > start_ + size_)
      return false;

    return true;
  }

  // Returns true iff @p other intersects this range.
  bool Intersects(const AddressRange& other) const {
    if (other.start_ + other.size_ <= start_ ||
        other.start_ >= start_ + size_)
      return false;

    return true;
  }

  bool operator<(const AddressRange& other) const {
    // This assumes the Addess and Size types may only provide operator <.
    return start_ < other.start_ ||
        !(other.start_ < start_) && size_ < other.size_;
  }

  bool operator==(const AddressRange& other) const {
    // If neither is less, they have to be equal.
    return !(other < *this) && !(*this < other);
  }

  AddressType start() const { return start_; }
  SizeType size() const { return size_; }

 private:
  // Start of address range.
  AddressType start_;
  // Size of address range.
  SizeType size_;
};

template <typename AddressType, typename SizeType, typename ItemType>
AddressSpace<AddressType, SizeType, ItemType>::AddressSpace() {
}

template <typename AddressType, typename SizeType, typename ItemType>
bool AddressSpace<AddressType, SizeType, ItemType>::Insert(
    const Range& range,
    const ItemType& item,
    typename RangeMap::iterator* ret_it) {
  // Is there an intersecting block?
  RangeMap::iterator it = FindFirstIntersection(range);
  if (it != ranges_.end())
    return false;

  std::pair<RangeMap::iterator, bool> inserted =
      ranges_.insert(std::make_pair(range, item));
  DCHECK(inserted.second);
  if (ret_it != NULL)
    *ret_it = inserted.first;

  return true;
}

template <typename AddressType, typename SizeType, typename ItemType>
bool AddressSpace<AddressType, SizeType, ItemType>::Remove(const Range& range) {
  RangeMap::iterator it = ranges_.find(range);
  if (it == ranges_.end())
    return false;

  ranges_.erase(it);
  return true;
}

template <typename AddressType, typename SizeType, typename ItemType>
typename AddressSpace<AddressType, SizeType, ItemType>::RangeMap::const_iterator
AddressSpace<AddressType, SizeType, ItemType>::FindFirstIntersection(
    const Range& range) const {
  RangeMap::const_iterator it(ranges_.lower_bound(range));

  // There are three cases we need to handle here:
  // 1. An exact match.
  if (it != ranges_.end() && it->first == range)
    return it;

  // 2. Intersection with the next earlier (lower address or shorter) range.
  // Back up one if we can and test for intersection.
  if (it != ranges_.begin()) {
    RangeMap::const_iterator prev(it);
    --prev;

    if (prev->first.Intersects(range))
      return prev;
  }

  // 3. Intersection to a/the found block.
  if (it != ranges_.end() && it->first.Intersects(range))
    return it;

  return ranges_.end();
}

template <typename AddressType, typename SizeType, typename ItemType>
typename AddressSpace<AddressType, SizeType, ItemType>::RangeMap::iterator
AddressSpace<AddressType, SizeType, ItemType>::FindFirstIntersection(
    const Range& range) {
  RangeMap::iterator it(ranges_.lower_bound(range));

  // There are three cases we need to handle here:
  // 1. An exact match.
  if (it != ranges_.end() && it->first == range)
    return it;

  // 2. Intersection with the next earlier (lower address or shorter) range.
  // Back up one if we can and test for intersection.
  if (it != ranges_.begin()) {
    RangeMap::iterator prev(it);
    --prev;

    if (prev->first.Intersects(range))
      return prev;
  }

  // 3. Intersection to a/the found block.
  if (it != ranges_.end() && it->first.Intersects(range))
    return it;

  return ranges_.end();
}

template <typename AddressType, typename SizeType, typename ItemType>
typename AddressSpace<AddressType, SizeType, ItemType>::RangeMap::const_iterator
AddressSpace<AddressType, SizeType, ItemType>::FindContaining(
    const Range& range) const {
  // If there is a containing range, it must be the first intersection.
  RangeMap::const_iterator it(FindFirstIntersection(range));
  if (it != ranges_.end() && it->first.Contains(range))
    return it;

  return ranges_.end();
}

template <typename AddressType, typename SizeType, typename ItemType>
typename AddressSpace<AddressType, SizeType, ItemType>::RangeMap::iterator
AddressSpace<AddressType, SizeType, ItemType>::FindContaining(
    const Range& range) {
  // If there is a containing range, it must be the first intersection.
  RangeMap::iterator it(FindFirstIntersection(range));
  if (it != ranges_.end() && it->first.Contains(range))
    return it;

  return ranges_.end();
}

} // namespace image_util

#endif  // SAWBUCK_IMAGE_UTIL_ADDRESS_SPACE_H_
