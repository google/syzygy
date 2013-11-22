// Copyright 2012 Google Inc. All Rights Reserved.
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
// Declares AddressRange, AddressSpace and AddressRangeMap. AddressRange is
// a primitive used by AddressSpace and AddressRangeMap. AddressSpace is useful
// for maintaining a collection of objects that map to ranges of bytes in some
// finite address-space, ensuring that they do not collide. An AddressRangeMap
// is a specialized version of an AddressSpace where the stored objects are
// themselves AddressRanges, with special semantics for simplifying the
// representation.

#ifndef SYZYGY_CORE_ADDRESS_SPACE_H_
#define SYZYGY_CORE_ADDRESS_SPACE_H_

#include <algorithm>
#include <iosfwd>
#include <map>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "syzygy/core/address_space_internal.h"
#include "syzygy/core/serialization.h"

namespace core {

// Forward declaration.
template <typename AddressType, typename SizeType> class AddressRange;

// An address space is a mapping from a set of non-overlapping address ranges
// (AddressSpace::Range), each of non-zero size, to an ItemType.
template <typename AddressType, typename SizeType, typename ItemType>
class AddressSpace {
 public:
  // Typedef we use for convenience throughout.
  typedef AddressRange<AddressType, SizeType> Range;
  typedef std::map<Range, ItemType> RangeMap;
  typedef typename std::map<Range, ItemType>::iterator RangeMapIter;
  typedef typename std::map<Range, ItemType>::const_iterator RangeMapConstIter;
  typedef std::pair<RangeMapConstIter, RangeMapConstIter> RangeMapConstIterPair;
  typedef std::pair<RangeMapIter, RangeMapIter> RangeMapIterPair;

  // STL-like type definitions
  // @{
  typedef typename RangeMapIter iterator;
  typedef typename RangeMapConstIter const_iterator;
  typedef typename RangeMap::value_type value_type;
  // @}

  // Create an empty address space.
  AddressSpace();

  // Insert @p range mapping to @p item unless @p range intersects
  // an existing range.
  // @param range the range to insert.
  // @param item the item to associate with @p range.
  // @param ret_it on success, returns an iterator to the inserted item.
  // @returns true iff @p range inserted.
  bool Insert(const Range& range,
              const ItemType& item,
              typename RangeMap::iterator* ret_it = NULL);

  // Insert @p range mapping to @p item or return the existing item exactly
  // matching @p range.
  //
  // @param range the range of the item to get or insert.
  // @param item the item to associate with @p range if none already exists.
  // @param ret_it on success, returns an iterator to the found or inserted
  //     item if not NULL.
  //
  // @returns true if the {range, item} pair is inserted or if there exists
  //     an item exactly matching range; otherwise false, indicating that a
  //     conflict/error has been detected.
  bool FindOrInsert(const Range& range,
                    const ItemType& item,
                    typename RangeMap::iterator* ret_it = NULL);

  // Inserts @p range mapping to @p item, unless @p range intersects
  // an existing range and does not contain it. Any existing ranges it contains
  // will be removed. If a range exists that contains @p range, returns true
  // and returns the iterator to that range.
  // @param range the range to insert.
  // @param item the item to associate with @p range.
  // @param ret_it on success, returns an iterator to the inserted item.
  // @returns true on success.
  //
  // Example insertions:
  //
  // Existing : aaaa    bbbb
  // Inserting: xxxxxxxxxxxx
  // Result   : cccccccccccc
  //
  // Existing : aaaaaa  bbbbbb
  // Inserting:   xxxxxxxxxx
  // Result   : failure!
  bool SubsumeInsert(const Range& range,
                     const ItemType& item,
                     typename RangeMap::iterator* ret_it = NULL);

  // Inserts @p range mapping to @p item. If this range overlaps any existing
  // blocks, all of the overlapping blocks will be merged to form one single
  // block. This insertion can never fail. If @p ret_it is non-null, return the
  // iterator to the inserted block, or if @p range lies entirely within an
  // existing block, returns the iterator to that block.
  // @param range the range to insert.
  // @param item the item to associate with @p range.
  // @param ret_it on success, returns an iterator to the inserted item.
  //
  // Example insertions:
  //
  // Existing : aaaa    bbbb
  // Inserting: xxxxxxxxxxxx
  // Result   : cccccccccccc
  //
  // Existing : aaaaaa  bbbbbb
  // Inserting:   xxxxxxxxxx
  // Result   : cccccccccccccc
  void MergeInsert(const Range& range,
                   const ItemType& item,
                   typename RangeMap::iterator* ret_it = NULL);

  // Remove the range that exactly matches @p range.
  // Returns true iff @p range is removed.
  bool Remove(const Range& range);
  // Remove the item at position @p it.
  void Remove(RangeMapIter it) { ranges_.erase(it); }
  // Remove the items in the given range.
  void Remove(RangeMapIterPair its) { ranges_.erase(its.first, its.second); }
  void Remove(RangeMapIter it1, RangeMapIter it2) { ranges_.erase(it1, it2); }
  // Remove all items from the address space.
  void Clear() { ranges_.clear(); }

  const RangeMap& ranges() const { return ranges_; }
  const bool empty() const { return ranges_.empty(); }
  const size_t size() const { return ranges_.size(); }

  // Finds the first contained range that intersects @p range.
  RangeMapConstIter FindFirstIntersection(const Range& range) const;
  RangeMapIter FindFirstIntersection(const Range& range);

  // Caution must be taken in using the non-const version of these! It is up
  // to the user not to change the values of any underlying ranges so as to
  // invalidate the non-overlapping range property of the address space. The
  // non-const iterator access is only intended for deletion of entire ranges.
  RangeMapConstIter begin() const { return ranges_.begin(); }
  RangeMapIter begin() { return ranges_.begin(); }
  RangeMapConstIter end() const { return ranges_.end(); }
  RangeMapIter end() { return ranges_.end(); }

  // Returns a pair of iterators that iterate over all ranges
  // intersecting @p range.
  RangeMapConstIterPair FindIntersecting(const Range& range) const;
  RangeMapIterPair FindIntersecting(const Range& range);

  // Returns true if the given range intersects any range currently in the
  // address space.
  bool Intersects(const Range& range) const;
  bool Intersects(AddressType address, SizeType size = 1) const {
    return Intersects(Range(address, size));
  }

  // Returns true if the given range is contained exactly in the address
  // space.
  bool ContainsExactly(const Range& range) const;
  bool ContainsExactly(AddressType address, SizeType size = 1) const {
    return ContainsExactly(Range(address, size));
  }

  // Returns true if the given range is contained by exactly one range in the
  // address space.
  bool Contains(const Range& range) const;
  bool Contains(AddressType address, SizeType size = 1) const {
    return Contains(Range(address, size));
  }

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
  typedef AddressType Address;
  typedef SizeType Size;

  AddressRange() : start_(0), size_(0) {
  }

  AddressRange(const AddressType &start, const SizeType& size)
      : start_(start), size_(size) {
  }

  AddressRange(const AddressRange &other)
      : start_(other.start_), size_(other.size_) {
  }

  void operator=(const AddressRange &other) {
    start_ = other.start_;
    size_ = other.size_;
  }

  // @returns true if this range is empty.
  bool IsEmpty() const { return size_ == 0; }

  // Determines if a given address range is contained within this range.
  // @param other The range to check.
  // @param addr Start address of the range to check.
  // @param size The size of the other range to check.
  // @returns true iff @p other is contained within this range.
  bool Contains(const AddressRange& other) const {
    if (other.start_ < start_ || other.end() > end())
      return false;

    return true;
  }
  bool Contains(AddressType addr, SizeType size = 1) const {
    return Contains(AddressRange(addr, size));
  }

  // Determines if a given range intersects this range.
  // @param other The range to test.
  // @param addr Start address of the range to check.
  // @param size The size of the other range to check.
  // @returns true iff @p other intersects this range.
  bool Intersects(const AddressRange& other) const {
    if (other.end() <= start_ || other.start_ >= end())
      return false;

    return true;
  }
  bool Intersects(AddressType addr, SizeType size = 1) const {
    return Intersects(AddressRange(addr, size));
  }

  // @name Comparison operators. These are for the purposes of the map that we
  //     use for tracking the address space.
  // @{
  bool operator<(const AddressRange& other) const {
    // This assumes the Address and Size types provide operator <.
    return internal::CompleteAddressRangeLess<AddressRange>()(*this, other);
  }

  bool operator==(const AddressRange& other) const {
    // If neither is less, they have to be equal. That is, they conflict as
    // far as the address-space is concerned.
    return !(other < *this) && !(*this < other);
  }

  bool operator!=(const AddressRange& other) const {
    return !operator==(other);
  }
  // @}

  AddressType start() const { return start_; }
  AddressType end() const { return start_ + size_; }
  SizeType size() const { return size_; }

  bool Save(OutArchive* out_archive) const {
    DCHECK(out_archive != NULL);
    return out_archive->Save(start_) && out_archive->Save(size_);
  }

  bool Load(InArchive* in_archive) {
    DCHECK(in_archive != NULL);
    return in_archive->Load(&start_) && in_archive->Load(&size_);
  }

 private:
  // Start of address range.
  AddressType start_;
  // Size of address range.
  SizeType size_;
};

// An AddressRangeMap is used for keeping track of data in one address space
// that has some relationship with data in another address space. Mappings are
// stored as pairs of addresses, one from the 'source' address-space and one
// from the 'destination' address-space. The ranges are sorted based on the
// source ranges, and the source ranges must be disjoint. The data structure
// ensures that the representation used is minimal in the following sense:
// a pair of address-range mappings that have the same size in both images and
// are consecutive in each image will be merged. For example, consider a
// mapping containing the two pairs of ranges:
//
//   [0, 10) maps to [1000, 1010), and
//   [10, 30) maps to [1010, 1030).
//
// This is more succinctly represented as (assuming linearity of the underlying
// relationship):
//
//   [0, 30) maps to [1000, 1030).
//
// However, a pair of mappings like:
//
//   [0, 10) maps to [1000, 1010), and
//   [10, 30) maps to [1010, 1036)
//
// should not be merged, as even though they are contiguous in both address
// spaces, the source and destination ranges are not of the same size for the
// second pair. Thus, we can't imply that the relationship holds for the pair
// [0, 30) and [1000, 1036).
template <typename SourceRangeType, typename DestinationRangeType>
class AddressRangeMap {
 public:
  typedef SourceRangeType SourceRange;
  typedef DestinationRangeType DestinationRange;
  typedef std::pair<SourceRange, DestinationRange> RangePair;
  typedef std::vector<RangePair> RangePairs;

  const RangePairs& range_pairs() const { return range_pairs_; }
  const RangePair& range_pair(size_t i) const { return range_pairs_[i]; }
  void clear() { range_pairs_.clear(); }
  bool empty() const { return range_pairs_.empty(); }
  size_t size() const { return range_pairs_.size(); }

  bool operator==(const AddressRangeMap& other) const {
    return range_pairs_ == other.range_pairs_;
  }

  bool operator!=(const AddressRangeMap& other) const {
    return range_pairs_ != other.range_pairs_;
  }

  // Determines if this is a simple mapping.
  //
  // A mapping is simple if there exists exactly one range, and the sizes of the
  // source and destination ranges are identical.
  //
  // @returns true if this mapping is simple, false otherwise.
  bool IsSimple() const {
    return range_pairs_.size() == 1 &&
        range_pairs_.front().first.size() == range_pairs_.front().second.size();
  }

  // Given a source range finds the range pair that encompasses it, if it
  // exists.
  //
  // @param sec_range the source range to search for.
  // @returns a pointer to the range pair, or NULL if none exists.
  const RangePair* FindRangePair(const SourceRange& src_range) const;

  // Given a source range finds the range pair that encompasses it, if it
  // exists.
  //
  // @param start the beginning of the source range to search for.
  // @param size the size of the source range to search for.
  // @returns a pointer to the range pair, or NULL if none exists.
  const RangePair* FindRangePair(typename SourceRange::Address start,
                                 typename SourceRange::Size size) const {
    return FindRangePair(SourceRange(start, size));
  }

  // Determines if the given source address range is fully mapped.
  //
  // @param src_range the source range to confirm.
  // @returns true if @p src_range is fully mapped, false otherwise.
  bool IsMapped(const SourceRange& src_range) const;

  // Determines if the given source address range is fully mapped.
  //
  // @param start the beginning of the source range to confirm.
  // @param size the size of the source range to confirm.
  // @returns true if the source range is fully mapped, false otherwise.
  bool IsMapped(typename SourceRange::Address start,
                typename SourceRange::Size size) const {
    return IsMapped(SourceRange(start, size));
  }

  // Adds a new pair of ranges to the map.
  //
  // This method allows insertions at arbitrary locations, but may consequently
  // be slower as a reallocation may be required.
  //
  // @param src_range the source range of the mapping to be inserted.
  // @param dst_range the destination range of the mapping to be inserted.
  // @returns true on success, false otherwise.
  bool Insert(const SourceRange& src_range, const DestinationRange& dst_range);

  // Pushes a new pair of ranges to the tail end of the source address range.
  //
  // This method is amortized O(1) and is simpler than Insert if the mapping
  // is being created in sequential order in the source address space. This will
  // fail if @p src_range is not greater than all existing ranges.
  //
  // @param src_range the source range of the mapping to be inserted.
  // @param dst_range the destination range of the mapping to be inserted.
  // @returns true on success, false otherwise.
  bool Push(const SourceRange& src_range, const DestinationRange& dst_range);

  // Computes the inverse of this mapping, returning the number of address
  // ranges mappings that were unable to be inverted. If DestinationRange and
  // SourceRange are the same type this may be performed in-place.
  //
  // The inversion is deterministic. When conflicting destination ranges are
  // found, earlier start addresses and shorter lengths have priority.
  //
  // @param inverted a pointer to the AddressRangeMap that will be populated
  //     with the inverted address range map.
  // @returns the number of conflicting address ranges that were unable to be
  //     inverted.
  size_t ComputeInverse(
      AddressRangeMap<DestinationRange, SourceRange>* inverted) const;

  // Rejigs a mapping by changing the underlying address-space that is being
  // mapped. This inserts a range of unmapped data in the source range, pushing
  // all mapped ranges that are beyond the newly unmapped data. If a mapped
  // source range intersects the unmapped range being inserted, this mapping
  // is split. During a split, the first of the two split ranges will maintain
  // linearity when possible.
  //
  // For example, consider the following address range map (expressed as
  // [start, end) ranges):
  //
  // [0, 10) -> [1000, 1010), [20, 30) -> [1020, 1030)
  //
  // After inserting an unmapped range at offset 25 size 5 the mapping will be:
  //
  // [0, 10) -> [1000, 1010), [20, 25) -> [1020, 1025), [30, 35) -> [1025, 1030)
  //
  // Simple splitting can fail in a very unlikely edge case. Consider the case
  // where the source range has size N > 1 and the destination range has size 1.
  // Now consider splitting the source range. We only have one byte of
  // destination range, so how to split that into two? The only solution is to
  // duplicate the destination range, which may make the mapping no longer
  // invertible.
  //
  // @param unmapped the unmapped source range to insert.
  void InsertUnmappedRange(const SourceRange& unmapped);

  // Modifies a mapping by changing the underlying address-space that is being
  // mapped. This removes a source range, erasing any mappings over that range
  // and shifting all mappings beyond that range to the left, as necessary. If
  // any mappings intersect the range being removed they will be split in such a
  // way as to keep the individual mappings linear, if possible.
  //
  // For example, consider the following address range map (expressed as
  // [start, end) ranges):
  //
  // [0, 10) -> [1000, 1010), [20, 30) -> [1020, 1030)
  //
  // After removing the source range [5, 20), the mapping will be:
  //
  // [0, 5) -> [1000, 1005), [5, 15) -> [1020, 1030)
  //
  // @param mapped the mapped source range to remove.
  void RemoveMappedRange(const SourceRange& mapped);

  // For serialization.
  bool Save(OutArchive* out_archive) const {
    DCHECK(out_archive != NULL);
    return out_archive->Save(range_pairs_);
  }
  bool Load(InArchive* in_archive) {
    DCHECK(in_archive != NULL);
    return in_archive->Load(&range_pairs_);
  }

 private:
  // Runs a lower bound search with the provided src_range and a made up
  // destination range. The returned iterator either intersects src_range, is
  // strictly greater than it, or is 'end()'.
  typename RangePairs::const_iterator LowerBound(
      const SourceRange& src_range) const;

  // Stores the mapping.
  RangePairs range_pairs_;
};

template <typename AddressType, typename SizeType, typename ItemType>
AddressSpace<AddressType, SizeType, ItemType>::AddressSpace() {
}

template <typename AddressType, typename SizeType, typename ItemType>
bool AddressSpace<AddressType, SizeType, ItemType>::Insert(
    const Range& range,
    const ItemType& item,
    typename RangeMap::iterator* ret_it) {
  // We can't insert empty ranges.
  if (range.IsEmpty())
    return false;

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
bool AddressSpace<AddressType, SizeType, ItemType>::FindOrInsert(
    const Range& range,
    const ItemType& item,
    typename RangeMap::iterator* ret_it) {
  // We can't insert empty ranges.
  if (range.IsEmpty())
    return false;

  // Is there already an existing block exactly matching that range? If so,
  // return it.
  RangeMap::iterator it = FindFirstIntersection(range);
  if (it != ranges_.end()) {
    if (ret_it != NULL)
      *ret_it = it;
    return range == it->first && item == it->second;
  }

  std::pair<RangeMap::iterator, bool> inserted =
      ranges_.insert(std::make_pair(range, item));
  DCHECK(inserted.second);
  if (ret_it != NULL)
    *ret_it = inserted.first;

  return true;
}

template <typename AddressType, typename SizeType, typename ItemType>
bool AddressSpace<AddressType, SizeType, ItemType>::SubsumeInsert(
    const Range& range,
    const ItemType& item,
    typename RangeMap::iterator* ret_it) {
  // We can't insert empty ranges.
  if (range.IsEmpty())
    return false;

  RangeMapIterPair its = FindIntersecting(range);

  // We only need to check how we intersect the first and last ranges; we
  // are guaranteed to subsume all others.
  if (its.first != its.second) {
    RangeMapIter it = its.first;

    // Check the first range.
    DCHECK(range.Intersects(it->first));
    // We do not contain the first returned range?
    if (!range.Contains(it->first)) {
      // We do not contain it, it does not contain us. We have a proper
      // intersection with them and the insertion fails.
      if (!it->first.Contains(range))
        return false;

      // They strictly contain us. There should be only one of them, and we
      // should return it.
      DCHECK_EQ(1, std::distance(its.first, its.second));
      if (ret_it != NULL)
        *ret_it = its.first;
      return true;
    }

    // We now check the second range. If we got here, the first range is a
    // proper subset of the range we're trying to add. We need to contain the
    // second range in order for the insertion to proceed. If we do not contain
    // it, we know it starts within our range, and finished outside of it and
    // therefore it is a proper intersection.
    it = its.second;
    --it;
    DCHECK(range.Intersects(it->first));
    if (!range.Contains(it->first))
      return false;
  }

  ranges_.erase(its.first, its.second);

  std::pair<RangeMap::iterator, bool> inserted =
      ranges_.insert(std::make_pair(range, item));
  DCHECK(inserted.second);
  if (ret_it != NULL)
    *ret_it = inserted.first;

  return true;
}

template <typename AddressType, typename SizeType, typename ItemType>
void AddressSpace<AddressType, SizeType, ItemType>::MergeInsert(
    const Range& range,
    const ItemType& item,
    typename RangeMap::iterator* ret_it) {
  // We can't insert empty ranges.
  if (range.IsEmpty())
    return;

  RangeMapIterPair its = FindIntersecting(range);

  AddressType start_addr = range.start();
  size_t length = range.size();

  // Have overlap with existing blocks?
  if (its.first != its.second) {
    // Find start address of new block. This is the min of the requested range,
    // or the beginning of the first intersecting block.
    RangeMap::iterator it_first = its.first;
    DCHECK(it_first != ranges_.end());
    start_addr = std::min(range.start(), it_first->first.start());

    // Find end address of new block. This is the max of the requested range,
    // or the end of the last intersecting block.
    RangeMap::iterator it_last = its.second;
    --it_last;
    DCHECK(it_last != ranges_.end());
    AddressType end_addr = std::max(range.end(), it_last->first.end());

    // Erase the existing blocks.
    length = end_addr - start_addr;
    ranges_.erase(its.first, its.second);
  }

  // Insert the new block.
  Range new_range(start_addr, length);
  std::pair<RangeMap::iterator, bool> inserted =
      ranges_.insert(std::make_pair(new_range, item));
  DCHECK(inserted.second);
  if (ret_it != NULL)
    *ret_it = inserted.first;

  return;
}

template <typename AddressType, typename SizeType, typename ItemType>
bool AddressSpace<AddressType, SizeType, ItemType>::Remove(const Range& range) {
  // We can't remove empty ranges.
  if (range.IsEmpty())
    return false;

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
  return const_cast<AddressSpace*>(this)->FindFirstIntersection(range);
}

template <typename AddressType, typename SizeType, typename ItemType>
typename AddressSpace<AddressType, SizeType, ItemType>::RangeMap::iterator
AddressSpace<AddressType, SizeType, ItemType>::FindFirstIntersection(
    const Range& range) {
  // Empty items do not exist in the address-space.
  if (range.IsEmpty())
    return ranges_.end();

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
typename AddressSpace<AddressType, SizeType, ItemType>::RangeMapConstIterPair
AddressSpace<AddressType, SizeType, ItemType>::FindIntersecting(
    const Range& range) const {
  return const_cast<AddressSpace*>(this)->FindIntersecting(range);
}

template <typename AddressType, typename SizeType, typename ItemType>
typename AddressSpace<AddressType, SizeType, ItemType>::RangeMapIterPair
AddressSpace<AddressType, SizeType, ItemType>::FindIntersecting(
    const Range& range) {
  // Empty ranges find nothing.
  if (range.IsEmpty())
    return std::make_pair(ranges_.end(), ranges_.end());

  // Find the start of the range first.
  RangeMap::iterator begin(FindFirstIntersection(range));

  // Then the end.
  RangeMap::iterator end(ranges_.lower_bound(
      Range(range.start() + range.size(), 1)));

  // Ensure that the relationship begin <= end holds, so that we may always
  // iterate over the returned range. It is possible that begin == end(),
  // and end != end(), which can cause problems. This is specifically the case
  // when there is no intersection with @p range, but that there is at least
  // one range beyond @p range.
  if (begin == ranges_.end())
    begin = end;

  // Since we search for the first range that starts at or after the end
  // of the input range, the range we find should never be intersecting.
  DCHECK(end == ranges_.end() || !end->first.Intersects(range));

  return std::make_pair(begin, end);
}

template <typename AddressType, typename SizeType, typename ItemType>
bool AddressSpace<AddressType, SizeType, ItemType>::Intersects(
    const Range& range) const {
  RangeMapConstIterPair its = FindIntersecting(range);
  return (its.first != its.second);
}

template <typename AddressType, typename SizeType, typename ItemType>
bool AddressSpace<AddressType, SizeType, ItemType>::ContainsExactly(
    const Range& range) const {
  RangeMapConstIterPair its = FindIntersecting(range);
  if (its.first == its.second)
    return false;
  return its.first->first == range;
}

template <typename AddressType, typename SizeType, typename ItemType>
bool AddressSpace<AddressType, SizeType, ItemType>::Contains(
    const Range& range) const {
  RangeMapConstIterPair its = FindIntersecting(range);
  if (its.first == its.second)
    return false;
  return its.first->first.Contains(range);
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

template <typename SourceRangeType, typename DestinationRangeType>
const std::pair<SourceRangeType, DestinationRangeType>*
AddressRangeMap<SourceRangeType, DestinationRangeType>::FindRangePair(
    const SourceRange& src_range) const {
  // No empty range exists in the mapping.
  if (src_range.IsEmpty())
    return NULL;

  // Find the first existing source range that is not less than src_range.
  // The returned iterator either intersects src_range, or is strictly greater
  // than it.
  RangePairs::const_iterator it = LowerBound(src_range);

  if (it == range_pairs_.end())
    return NULL;
  if (it->first.Contains(src_range))
    return &(*it);
  return NULL;
}

template <typename SourceRangeType, typename DestinationRangeType>
bool AddressRangeMap<SourceRangeType, DestinationRangeType>::IsMapped(
    const SourceRange& src_range) const {
  // By definition no empty range is mapped.
  if (src_range.IsEmpty())
    return false;

  // Find the first existing source range that is not less than src_range.
  // The returned iterator either intersects src_range, or is strictly greater
  // than it.
  RangePairs::const_iterator it = LowerBound(src_range);

  // Step through the successive mapped ranges and see if they cover src_range.
  typename SourceRange::Address position = src_range.start();
  while (true) {
    // No more mapped source ranges? Then src_range is not covered.
    if (it == range_pairs_.end())
      return false;

    // Is there an uncovered gap between position and the next mapped source
    // range? Then src_range is not covered.
    if (position < it->first.start())
      return false;

    // Step over this mapped source range and see if we're completely covered.
    position = it->first.end();
    if (position >= src_range.end())
      return true;

    ++it;
  }
}

template <typename SourceRangeType, typename DestinationRangeType>
bool AddressRangeMap<SourceRangeType, DestinationRangeType>::Insert(
    const SourceRange& src_range, const DestinationRange& dst_range) {
  // No empty ranges may be inserted in the mapping.
  if (src_range.IsEmpty() || dst_range.IsEmpty())
    return false;

  // Find the first existing source range that is not less than src_range.
  RangePairs::iterator it = std::lower_bound(
      range_pairs_.begin(),
      range_pairs_.end(),
      std::make_pair(src_range, dst_range),
      internal::RangePairLess<SourceRange, DestinationRange>());

  // The search fell off the end of the vector? Push it to the back.
  if (it == range_pairs_.end())
    return Push(src_range, dst_range);

  // Does this source range overlap at all with the existing one?
  if (it->first.Intersects(src_range))
    return false;

  // At this point we know that 'it' points to a source range that is greater
  // than src_range. There are now 4 possibilities:
  // 1. It can be merged with the source range to the left, at 'it - 1'.
  // 2. It can be merged with the source range to the right, at 'it'.
  // 3. It can be merged with both the source range to the left and the right.
  // 4. It can't be merged at all, and needs to be inserted.

  // Determine in which directions we need to merge.
  bool merge_left = false;
  bool merge_right = false;
  if (src_range.size() == dst_range.size()) {
    // If there is an element to the left, see if we can merge with it.
    if (it != range_pairs_.begin()) {
      RangePairs::iterator it_left = it - 1;
      if (it_left->first.size() == it_left->second.size() &&
          it_left->first.end() == src_range.start() &&
          it_left->second.end() == dst_range.start()) {
        merge_left = true;
      }
    }

    if (it->first.size() == it->second.size() &&
        src_range.end() == it->first.start() &&
        dst_range.end() == it->second.start()) {
      merge_right = true;
    }
  }

  // Don't need to change sizes because we're merging in only one direction?
  if (merge_left != merge_right) {
    SourceRange merged_src_range;
    DestinationRange merged_dst_range;
    if (merge_left) {
      --it;
      merged_src_range = SourceRange(it->first.start(),
                                     it->first.size() + src_range.size());
      merged_dst_range = DestinationRange(it->second.start(),
                                          it->second.size() + dst_range.size());
    } else {
      merged_src_range = SourceRange(src_range.start(),
                                     src_range.size() + it->first.size());
      merged_dst_range = DestinationRange(dst_range.start(),
                                          dst_range.size() + it->second.size());
    }

    *it = std::make_pair(merged_src_range, merged_dst_range);
    return true;
  }

  // Merging in both directions and shrinking?
  if (merge_left && merge_right) {
    RangePairs::iterator it_left = it - 1;

    SourceRange merged_src_range(
        it_left->first.start(),
        it_left->first.size() + src_range.size() + it->first.size());
    DestinationRange merged_dst_range(
        it_left->second.start(),
        it_left->second.size() + dst_range.size() + it->second.size());

    *it_left = std::make_pair(merged_src_range, merged_dst_range);
    range_pairs_.erase(it);
    return true;
  }

  // If we get here then we're growing.
  range_pairs_.insert(it, std::make_pair(src_range, dst_range));
  return true;
}

template <typename SourceRangeType, typename DestinationRangeType>
bool AddressRangeMap<SourceRangeType, DestinationRangeType>::Push(
    const SourceRange& src_range, const DestinationRange& dst_range) {
  // We can't insert empty ranges.
  if (src_range.IsEmpty() || dst_range.IsEmpty())
    return false;

  if (!range_pairs_.empty()) {
    SourceRange& last_src_range = range_pairs_.back().first;

    // If we already have RangePairs in the list, then src_range must be beyond
    // the last SourceRange.
    if (!(last_src_range < src_range) || last_src_range.Intersects(src_range))
      return false;

    // Can we merge this new pair of ranges with the existing last pair of
    // ranges?
    DestinationRange& last_dst_range = range_pairs_.back().second;
    if (last_src_range.size() == last_dst_range.size() &&
        src_range.size() == dst_range.size() &&
        last_src_range.end() == src_range.start() &&
        last_dst_range.end() == dst_range.start()) {
      last_src_range = SourceRange(
          last_src_range.start(), last_src_range.size() + src_range.size());
      last_dst_range = DestinationRange(
          last_dst_range.start(), last_dst_range.size() + dst_range.size());
      return true;
    }
  }

  range_pairs_.push_back(std::make_pair(src_range, dst_range));
  return true;
}

template <typename SourceRangeType, typename DestinationRangeType>
size_t AddressRangeMap<SourceRangeType, DestinationRangeType>::ComputeInverse(
    AddressRangeMap<DestinationRangeType, SourceRangeType>* inverted) const {
  DCHECK(inverted != NULL);

  // Get a list of inverted range pairs.
  std::vector<std::pair<DestinationRangeType, SourceRangeType>>
      inverted_range_pairs;
  inverted_range_pairs.reserve(range_pairs_.size());
  for (size_t i = 0; i < range_pairs_.size(); ++i) {
    inverted_range_pairs.push_back(
        std::make_pair(range_pairs_[i].second, range_pairs_[i].first));
  }

  // We sort these with a custom sort functor so that a total ordering is
  // defined rather than the default partial ordering defined by AddressRange.
  std::sort(inverted_range_pairs.begin(),
            inverted_range_pairs.end(),
            internal::CompleteAddressRangePairLess<DestinationRangeType,
                                                   SourceRangeType>());

  // Push these back to the inverted address range map and count the conflicts.
  size_t conflicts = 0;
  inverted->clear();
  for (size_t i = 0; i < inverted_range_pairs.size(); ++i) {
    if (!inverted->Push(inverted_range_pairs[i].first,
                        inverted_range_pairs[i].second)) {
      ++conflicts;
    }
  }

  return conflicts;
}

template <typename SourceRangeType, typename DestinationRangeType>
typename AddressRangeMap<SourceRangeType, DestinationRangeType>::RangePairs::
    const_iterator
AddressRangeMap<SourceRangeType, DestinationRangeType>::LowerBound(
    const SourceRange& src_range) const {
  return std::lower_bound(
      range_pairs_.begin(),
      range_pairs_.end(),
      std::make_pair(src_range,
                     // We have to manually create a valid DestinationRange with
                     // a size > 0.
                     DestinationRange(typename DestinationRange::Address(),
                                      1)),
      internal::RangePairLess<SourceRange, DestinationRange>());
}

template <typename SourceRangeType, typename DestinationRangeType>
void AddressRangeMap<SourceRangeType, DestinationRangeType>::
    InsertUnmappedRange(const SourceRange& unmapped) {
  // Unmapping an empty range is a nop.
  if (unmapped.IsEmpty())
    return;

  typedef typename SourceRange::Size SrcSize;
  typedef typename DestinationRange::Size DstSize;
  typedef typename DestinationRange::Address DstAddr;

  // Walk backwards through the range pairs, fixing them as we go.
  for (size_t i = range_pairs_.size(); i > 0; --i) {
    RangePair& range_pair = range_pairs_[i - 1];
    SourceRange& src = range_pair.first;
    DestinationRange& dst = range_pair.second;

    // This range pair starts before the unmapped source range? We may have to
    // split it, but we can stop looking at earlier ranges.
    if (src.start() < unmapped.start()) {
      // Do we need a split?
      if (src.end() > unmapped.start()) {
        SrcSize src_size_before =
            static_cast<SrcSize>(unmapped.start() - src.start());
        SrcSize src_size_after =
            static_cast<SrcSize>(src.size() - src_size_before);

        DstAddr dst_start_before = dst.start();
        DstSize dst_size_before = src_size_before;
        DstAddr dst_start_after(0);
        DstSize dst_size_after(0);

        // Special case: The destination size is 1, so indivisible. In this
        // case we simply duplicate the destination range.
        if (dst.size() == 1) {
          dst_start_after = dst_start_before;
          dst_size_after = dst_size_before;
        } else {
          // If the destination range is smaller than the source range, it is
          // possible that dst_size_before consumes too much. In this case send
          // as much as possible to the left (so it is as close to linear as
          // possible), but leave some for the after the split.
          if (dst_size_before >= dst.size()) {
            dst_size_before = dst.size() - 1;
            dst_size_after = 1;
          }

          dst_start_after = dst_start_before + dst_size_before;
          dst_size_after = static_cast<DstSize>(dst.size() - dst_size_before);
        }

        // Create the range for after the split.
        RangePair pair_after(
            SourceRange(src.start() + src_size_before + unmapped.size(),
                        src_size_after),
            DestinationRange(dst_start_after, dst_size_after));

        // Fix the existing pair, which is now the pair before the split.
        src = SourceRange(src.start(), src_size_before);
        dst = DestinationRange(dst_start_before, dst_size_before);

        // Insert the the new range. This invalidates range_pair, src and dst
        // hence the need to do it at the very end.
        range_pairs_.insert(range_pairs_.begin() + i, pair_after);
      }

      return;
    }

    // Shift this range to the right.
    src = SourceRange(src.start() + unmapped.size(), src.size());
  }
}

template <typename SourceRangeType, typename DestinationRangeType>
void AddressRangeMap<SourceRangeType, DestinationRangeType>::
    RemoveMappedRange(const SourceRange& mapped) {
  // Removing an empty range is a nop.
  if (mapped.IsEmpty())
    return;

  typedef typename SourceRange::Size SrcSize;
  typedef typename DestinationRange::Size DstSize;
  typedef typename DestinationRange::Address DstAddr;

  // Special case: no source ranges to modify.
  if (range_pairs_.size() == 0)
    return;

  // Walk backwards through the range pairs, fixing them as we go.
  size_t i = range_pairs_.size();
  for (; i > 0; --i) {
    RangePair& range_pair = range_pairs_[i - 1];
    SourceRange& src = range_pair.first;
    DestinationRange& dst = range_pair.second;

    // This range pair starts before the end of the range we want to unmap?
    // Then we've finished fixing ranges that simply need to be shifted.
    if (src.start() < mapped.end())
      break;

    // Shift this range to the left.
    src = SourceRange(src.start() - mapped.size(), src.size());
  }

  // At this point we've found the first range that is not beyond the
  // end of mapped. Now we want to find the first range that is completely
  // before mapped.
  size_t end_affected_ranges = i;
  for (; i > 0; --i) {
    RangePair& range_pair = range_pairs_[i - 1];
    SourceRange& src = range_pair.first;
    DestinationRange& dst = range_pair.second;

    if (src.end() <= mapped.start())
      break;
  }
  size_t begin_affected_ranges = i;

  // It's possible that the affected ranges are off the end of the vector,
  // in which case there is absolutely nothing to do.
  if (begin_affected_ranges >= range_pairs_.size())
    return;

  // At this point the ith through (end_affected_ranges - 1)th ranges intersect
  // the range to be removed. The two endpoints may need to be split, but
  // everything between them needs to be deleted. We inspect each endpoint and
  // split them if need be.

  // Does the ith range need to split?
  if (range_pairs_[begin_affected_ranges].first.start() < mapped.start()) {
    RangePair& range_pair = range_pairs_[begin_affected_ranges];
    SourceRange& src = range_pair.first;
    DestinationRange& dst = range_pair.second;

    SrcSize src_size_left = mapped.start() - src.start();
    DstSize dst_size_left = src_size_left;
    if (dst_size_left > dst.size())
      dst_size_left = dst.size();

    // Special case: this element needs to be both left split and right split.
    if (begin_affected_ranges == end_affected_ranges - 1 &&
        mapped.end() < src.end()) {
      // Split in such as way as to prefer linear mappings. If being linear on
      // the left leaves no destination range on the right, shuffle a byte
      // between the two.
      SrcSize src_size_right = src.end() - mapped.end();
      DstSize dst_size_right = src_size_right;
      if (dst_size_left + dst_size_right > dst.size()) {
        dst_size_right = dst.size() - dst_size_left;
        if (dst_size_right == 0) {
          ++dst_size_right;
          --dst_size_left;
        }
      }
      DCHECK_GT(dst_size_left, 0u);
      DCHECK_GT(dst_size_right, 0u);
      DCHECK_LE(dst_size_left + dst_size_right, dst.size());
      DstAddr dst_start_right = dst.end() - dst_size_right;

      src = SourceRange(src.start(), src_size_left);
      dst = DestinationRange(dst.start(), dst_size_left);

      // We do this last as it invalidates src and dst.
      range_pairs_.insert(
          range_pairs_.begin() + begin_affected_ranges + 1,
          std::make_pair(SourceRange(mapped.start(), src_size_right),
                         DestinationRange(dst_start_right, dst_size_right)));

      return;
    }

    src = SourceRange(src.start(), src_size_left);
    dst = DestinationRange(dst.start(), dst_size_left);
    ++begin_affected_ranges;
  }

  // Does the (end_affected_ranges - 1)th range need to be split?
  if (range_pairs_[end_affected_ranges - 1].first.end() > mapped.end()) {
    RangePair& range_pair = range_pairs_[end_affected_ranges - 1];
    SourceRange& src = range_pair.first;
    DestinationRange& dst = range_pair.second;

    SrcSize src_size = src.end() - mapped.end();
    DstSize dst_size = src_size;
    if (dst_size > dst.size())
      dst_size = dst.size();

    src = SourceRange(src.end() - src_size - mapped.size(), src_size);
    dst = DestinationRange(dst.end() - dst_size, dst_size);
    --end_affected_ranges;
  }

  // Now we have that the ranges [begin_affected_ranges, end_affected_ranges)
  // need to simply be erased.
  if (begin_affected_ranges < end_affected_ranges)
    range_pairs_.erase(range_pairs_.begin() + begin_affected_ranges,
                       range_pairs_.begin() + end_affected_ranges);
}

// An ostream operator for AddressRanges.
template<typename AddressType, typename SizeType>
std::ostream& operator<<(
    std::ostream& str,
    const AddressRange<AddressType, SizeType>& range) {
  str << "AddressRange(" << range.start() << ", " << range.size() << ")";
  return str;
}

}  // namespace core

#endif  // SYZYGY_CORE_ADDRESS_SPACE_H_
