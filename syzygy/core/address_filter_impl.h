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

// Computes the intersection of r1 and r2 as r3. Returns true if non-empty,
// false otherwise.
template<typename Range>
bool Intersect(const Range& r1, const Range& r2, Range* r3) {
  DCHECK(r3 != NULL);

  Range::Address start = r1.start();
  if (r2.start() > start)
    start = r2.start();

  Range::Address end = r1.end();
  if (r2.end() < end)
    end = r2.end();

  // The intersection is empty.
  if (end <= start)
    return false;

  *r3 = Range(start, end - start);
  return true;
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
  RangeSet::iterator it1 = marked_ranges_.lower_bound(Range(r.start(), 1));

  // If there is no such block, or it is completely past us, then we can cleanly
  // insert our range.
  if (it1 == marked_ranges_.end() || RangeLessThan()(r, *it1)) {
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

  // Delete the conflicting intervals.
  marked_ranges_.erase(it1, it2);

  // And insert the merged interval.
  CHECK(marked_ranges_.insert(Range(start, end - start)).second);
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

  // Delete the range of intersecting intervals.
  marked_ranges_.erase(it1, it2);

  // Reinsert the left tail if there is one.
  if (start < r.start()) {
    SizeType length = r.start() - start;
    std::pair<RangeSet::iterator, bool> result =
        marked_ranges_.insert(Range(start, length));
    DCHECK(result.second);
  }

  // Reinsert the right tail if there is one.
  if (end > r.end()) {
    SizeType length = end - r.end();
    CHECK(marked_ranges_.insert(Range(r.end(), length)).second);
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

}  // namespace core

#endif  // SYZYGY_CORE_ADDRESS_FILTER_IMPL_H_
