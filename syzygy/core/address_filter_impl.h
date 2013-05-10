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
// Implementation details of core::AddressFilter. This is only meant to be
// included directly from syzygy/core/address_filter.h.

#ifndef SYZYGY_CORE_ADDRESS_FILTER_IMPL_H_
#define SYZYGY_CORE_ADDRESS_FILTER_IMPL_H_

namespace core {

namespace internal {

// Computes the intersection of r1 and r2 as r3. Returns 0 if there was an
// intersection, -1 if r1 < r2, or 1 or r2 > 1.
template<typename Range>
int CompareAndIntersect(const Range& r1, const Range& r2, Range* r3) {
  DCHECK(r3 != NULL);

  Range::Address start = r1.start();
  if (r2.start() > start)
    start = r2.start();

  Range::Address end = r1.end();
  if (r2.end() < end)
    end = r2.end();

  // The intersection is empty.
  if (end <= start) {
    if (r1.start() < r2.start())
      return -1;
    else
      return 1;
  }

  *r3 = Range(start, end - start);
  return 0;
}

template<typename Range>
bool Intersect(const Range& r1, const Range& r2, Range* r3) {
  DCHECK(r3 != NULL);
  return CompareAndIntersect(r1, r2, r3) == 0;
}

}  // namespace internal

// This is the comparison operator used for sorting disjoint AddressRanges. It
// will indicate equality if two ranges overlap at all.
template<typename AddressType, typename SizeType>
struct AddressRangeLessThan {
  typedef AddressRange<AddressType, SizeType> Range;

  bool operator()(const Range& r1, const Range& r2) const {
    return r1.end() <= r2.start();
  }
};

template<typename AddressType, typename SizeType>
void AddressFilter<AddressType, SizeType>::Mark(const Range& range) {
  Range r;
  if (!internal::Intersect(extent_, range, &r))
    return;

  // Get the first range that is *not* less than the beginning of the range
  // to be inserted. Which means either it contains us, or it is past us.
  // We have to be careful to search for the byte just preceding the range we
  // want to mark, so that we can merge contiguous intervals properly. We also
  // have to be careful how we calculate that preceding byte, as it's not always
  // meaningful or possible.
  AddressType search = r.start();
  if (extent_.start() < search && search - 1 < search)
    search = search - 1;
  RangeSet::iterator it1 = marked_ranges_.lower_bound(Range(search, 1));

  // If there is no such block, or it is completely past us (and not adjoining),
  // then we can cleanly insert our range.
  if (it1 == marked_ranges_.end() || r.end() < it1->start()) {
    CHECK(marked_ranges_.insert(r).second);
    return;
  }

  // At this point we know that it1 points to a range that intersects with us in
  // some way. We keep the leftmost of it and our starting points.
  AddressType start = r.start();
  if (it1->start() < start)
    start = it1->start();

  // Now we want to find the rightmost range we intersect.
  AddressType end = r.end();
  RangeSet::iterator it2 = it1;
  RangeSet::iterator it2_prev = it2;
  while (it2 != marked_ranges_.end() && end >= it2->start()) {
    it2_prev = it2;
    ++it2;
  }
  DCHECK(it2_prev != marked_ranges_.end());

  // Keep track of the rightmost point of any intervals we intersect.
  if (it2_prev->end() > end)
    end = it2_prev->end();

  // Keep a hint so that we can do O(1) insertion.
  RangeSet::iterator hint = marked_ranges_.end();
  if (it1 != marked_ranges_.begin()) {
    hint = it1;
    --hint;
  }

  // Delete the conflicting intervals.
  marked_ranges_.erase(it1, it2);

  // And insert the merged interval.
  marked_ranges_.insert(hint, Range(start, end - start));
}

template<typename AddressType, typename SizeType>
void AddressFilter<AddressType, SizeType>::Unmark(const Range& range) {
  Range r;
  if (!internal::Intersect(extent_, range, &r))
    return;

  // Get the first range that is *not* less than the beginning of the range
  // to be inserted. Which means either it contains us, or it is past us.
  RangeSet::iterator it1 = marked_ranges_.lower_bound(Range(r.start(), 1));

  // If there is no such block, or it is completely past us, then there is
  // nothing to remove.
  if (it1 == marked_ranges_.end() || RangeLessThan()(r, *it1))
    return;

  // At this point we know that it1 points to a range that contains our
  // starting point. Keep track of the leftmost of these two.
  AddressType start = r.start();
  if (it1->start() < start)
    start = it1->start();

  // Now we want to find the rightmost range we intersect.
  AddressType end = r.end();
  RangeSet::iterator it2 = it1;
  RangeSet::iterator it2_prev = it2;
  while (it2 != marked_ranges_.end() && end >= it2->start()) {
    it2_prev = it2;
    ++it2;
  }
  DCHECK(it2_prev != marked_ranges_.end());

  // Keep track of the rightmost point of any intervals we intersect.
  if (it2_prev->end() > end)
    end = it2_prev->end();

  // Keep a hint so that we can do O(1) insertion.
  RangeSet::iterator hint = marked_ranges_.end();
  if (it1 != marked_ranges_.begin()) {
    hint = it1;
    --hint;
  }

  // Delete the range of intersecting intervals.
  marked_ranges_.erase(it1, it2);

  // Reinsert the left tail if there is one.
  if (start < r.start()) {
    SizeType length = r.start() - start;
    hint = marked_ranges_.insert(hint, Range(start, length));
  }

  // Reinsert the right tail if there is one.
  if (end > r.end()) {
    SizeType length = end - r.end();
    hint = marked_ranges_.insert(hint, Range(r.end(), length));
  }
}

template<typename AddressType, typename SizeType>
bool AddressFilter<AddressType, SizeType>::IsMarked(const Range& range) const {
  // Anything that falls outside of the image extent is by definition not
  // marked.
  Range r;
  if (!internal::Intersect(extent_, range, &r))
    return false;

  // Get the first r that is *not* less than the beginning of the range
  // to be inserted. Which means either it contains us, or it is past us.
  RangeSet::iterator it = marked_ranges_.lower_bound(Range(r.start(), 1));

  // If there is no such block, or it is completely past us, then our range
  // is not marked.
  if (it == marked_ranges_.end() || RangeLessThan()(r, *it))
    return false;

  // At this point we know there is some intersection between the query range
  // and the range pointed to by |it|. Contiguous ranges are merged by Mark, so
  // we only need to check |it|.
  return it->Contains(r);
}

template<typename AddressType, typename SizeType>
bool AddressFilter<AddressType, SizeType>::IsUnmarked(
    const Range& range) const {
  // Anything that falls outside of the image extent is by definition not
  // marked.
  Range r;
  if (!internal::Intersect(extent_, range, &r))
    return true;

  // Get the first range that is *not* less than the beginning of the range
  // to be inserted. Which means either it contains us, or it is past us.
  RangeSet::iterator it = marked_ranges_.lower_bound(
      Range(r.start(), 1));

  // If there is no such block then we are not marked.
  if (it == marked_ranges_.end())
    return true;

  // Otherwise, we are only completely unmarked if this range doesn't
  // intersect our query range at all.
  return !r.Intersects(*it);
}

template<typename AddressType, typename SizeType>
void AddressFilter<AddressType, SizeType>::Invert(AddressFilter* filter) const {
  DCHECK(filter != NULL);

  // We work with a temporary RangeSet and swap its contents later, handling
  // the case when 'filter == this'.
  filter->extent_ = extent_;
  RangeSet ranges;

  RangeSet::const_iterator it = marked_ranges_.begin();
  AddressType cursor = extent_.start();

  // Special case: The filter is empty.
  if (it == marked_ranges_.end()) {
    CHECK(filter->marked_ranges_.insert(extent_).second);
    return;
  }

  RangeSet::iterator hint = ranges.end();

  if (cursor < it->start())
    hint = ranges.insert(hint, Range(cursor, it->start() - cursor));
  cursor = it->end();
  ++it;

  for (; it != marked_ranges_.end(); ++it) {
    // The ranges must be discontiguous so this is always true.
    DCHECK_LT(cursor, it->start());
    hint = ranges.insert(hint, Range(cursor, it->start() - cursor));
    cursor = it->end();
  }

  if (cursor < extent_.end())
    ranges.insert(hint, Range(cursor, extent_.end() - cursor));

  filter->marked_ranges_.swap(ranges);
}

template<typename AddressType, typename SizeType>
void AddressFilter<AddressType, SizeType>::Intersect(
    const AddressFilter& other, AddressFilter* filter) const {
  DCHECK(filter != NULL);

  // By our definition the result has the same extent as |this|. This is
  // somewhat arbitrary.
  filter->extent_ = extent_;

  // We work with a temporary RangeSet and swap its contents later, handling
  // the case when 'filter == this'.
  RangeSet ranges;

  // We only need to iterate over those ranges that are in the intersection of
  // the extents of the two filters.
  Range extent;
  internal::Intersect(extent_, other.extent_, &extent);

  RangeSet::const_iterator it1 = marked_ranges_.lower_bound(
      Range(extent.start(), 1));
  RangeSet::const_iterator it1_end = marked_ranges_.lower_bound(
      Range(extent.end(), 1));

  RangeSet::const_iterator it2 = other.marked_ranges_.lower_bound(
      Range(extent.start(), 1));
  RangeSet::const_iterator it2_end = other.marked_ranges_.lower_bound(
      Range(extent.end(), 1));

  RangeSet::iterator hint = ranges.end();
  while (it1 != it1_end && it2 != it2_end) {
    // Calculate the intersection. If it is empty this returns information
    // regarding the relative ordering of the two intervals in question.
    Range range;
    int dir = internal::CompareAndIntersect(*it1, *it2, &range);

    switch (dir) {
      case -1: {
        // No intersection, and *it1 < *it2.
        ++it1;
        break;
      }

      case 0: {
        // We have intersecting intervals, so add their intersection to the
        // output.
        hint = ranges.insert(hint, range);

        // Advance the iterator with the lesser interval endpoint, or both of
        // them if they are equal.
        if (it1->end() < it2->end()) {
          ++it1;
        } else if (it2->end() < it1->end()) {
          ++it2;
        } else {
          ++it1;
          ++it2;
        }
        break;
      }

      case 1: {
        // No intersection, and *it2 < *it1.
        ++it2;
        break;
      }
    }
  }

  filter->marked_ranges_.swap(ranges);
}

// NOTE: The following are implemented using a lazy O(n log n) approach, when
//     they could be O(n). The code would be significantly more complicated and
//     for the limited use we will make of these things it's simply not worth
//     the effort.

template<typename AddressType, typename SizeType>
void AddressFilter<AddressType, SizeType>::Union(
    const AddressFilter& other, AddressFilter* filter) const {
  DCHECK(filter != NULL);

  // We work with a temporary AddressFilter and swap its contents later,
  // handling the case when 'filter == this'.
  filter->extent_ = extent_;
  AddressFilter temp(*this);

  // We only need to iterate over those ranges that are in the intersection of
  // the extents of the two filters.
  Range extent;
  internal::Intersect(extent_, other.extent_, &extent);
  RangeSet::const_iterator it = other.marked_ranges_.lower_bound(
      Range(extent.start(), 1));
  RangeSet::const_iterator it_end = other.marked_ranges_.lower_bound(
      Range(extent.end(), 1));

  for (; it != it_end; ++it)
    temp.Mark(*it);

  filter->marked_ranges_.swap(temp.marked_ranges_);
}

template<typename AddressType, typename SizeType>
void AddressFilter<AddressType, SizeType>::Subtract(
    const AddressFilter& other, AddressFilter* filter) const {
  DCHECK(filter != NULL);

  // We work with a temporary AddressFilter and swap its contents later,
  // handling the case when 'filter == this'.
  filter->extent_ = extent_;
  AddressFilter temp(*this);

  // We only need to iterate over those ranges that are in the intersection of
  // the extents of the two filters.
  Range extent;
  internal::Intersect(extent_, other.extent_, &extent);
  RangeSet::const_iterator it = other.marked_ranges_.lower_bound(
      Range(extent.start(), 1));
  RangeSet::const_iterator it_end = other.marked_ranges_.lower_bound(
      Range(extent.end(), 1));

  for (; it != it_end; ++it)
    temp.Unmark(*it);

  filter->marked_ranges_.swap(temp.marked_ranges_);
}

}  // namespace core

#endif  // SYZYGY_CORE_ADDRESS_FILTER_IMPL_H_
