// Copyright 2011 Google Inc.
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
// A templatized non-mapping container that enforces that each member is
// unique.

#ifndef SYZYGY_COMMON_UNIQUE_LIST_H_
#define SYZYGY_COMMON_UNIQUE_LIST_H_

#include <algorithm>
#include <list>
#include <map>

#include "base/logging.h"

namespace common {

// UniqueList is an STL-compatible list that supports most of the std::list
// interface and (eventually) performance characteristics but add uniqueness
// and searchability.
//
// Note that uniqueness is enforced on element insertion, but non-const
// iterators and references can be used to violate the uniqueness constraint.
// Don't do this!
//
// TODO(rogerm): The initial implementation is a simple wrapper over std::list
//     with a linear scan for uniqueness. A more sophisticated approach would
//     hybridize the list with some sort of map to provide faster search and
//     membership testing.
//
// @tparam ValueType The type of object stored in this container.
// @tparam Allocator The allocator used to create the objects that get stored
//     in this container.
template<typename ValueType,
         typename Allocator = std::allocator<ValueType> >
class UniqueList {
  typedef std::list<ValueType, Allocator> list_type;

 public:
  // STL compatible type traits.
  // @{
  typedef typename list_type::reference reference;
  typedef typename list_type::const_reference const_reference;
  typedef typename list_type::value_type value_type;
  typedef typename list_type::iterator iterator;
  typedef typename list_type::const_iterator const_iterator;
  typedef typename list_type::allocator_type allocator_type;
  typedef typename list_type::pointer pointer;
  typedef typename list_type::const_pointer const_pointer;
  typedef typename list_type::reverse_iterator reverse_iterator;
  typedef typename list_type::const_reverse_iterator const_reverse_iterator;
  typedef typename list_type::size_type size_type;
  // @}

  // Construct a unique container with the given uniqueness @p comparator
  // and @p allocator.
  //
  // This constructor degenerates to the default constructor.
  //
  // @param comparator The membership comparator to use. Defaults to a fresh
  //     instance of the comparator type specified as a template parameter.
  // @param allocator The element allocator to use. Defaults to a fresh
  //     instance of the allocator type specified as a template paramter.
  UniqueList(const allocator_type& allocator = allocator_type())
      : list_(allocator) {
  }

  // Construct a unique container with the given element sequence.
  //
  // Only the first instance of any duplicate element in the sequence is
  // retained.
  //
  // @param first an iterator to the first element in the sequence.
  // @param last an iterator denoting when the input sequence is finished.
  // @param comparator The membership comparator to use. Defaults to a fresh
  //     instance of the comparator type specified as a template parameter.
  // @param allocator The element allocator to use. Defaults to a fresh
  //     instance of the allocator type specified as a template paramter.
  template<typename InputIterator>
  UniqueList(InputIterator first,
             InputIterator last,
             const allocator_type& allocator = allocator_type())
      : list_(allocator) {
    insert(end(), first, last);
  }

  // Creates a copy of the given unique container.
  explicit UniqueList(const UniqueList& other)
      : list_(other.list_) {
  }

  // Returns an iterator to the first container element, in order.
  // @{
  iterator begin() { return list_.begin(); }
  const_iterator begin() const { return list_.begin(); }
  // @}

  // Returns an iterator one past the last container element, in order.
  // @{
  iterator end() { return list_.end(); }
  const_iterator end() const { return list_.end(); }
  // @}

  // Returns an iterator to the first container element, in reverse order.
  // @{
  reverse_iterator rbegin() { return list_.rbegin(); }
  const_reverse_iterator rbegin() const { return list_.rbegin(); }
  // @}

  // Returns an iterator one past the last container element, in reverse order.
  // @{
  reverse_iterator rend() { return list_.rend(); }
  const_reverse_iterator rend() const { return list_.rend(); }
  // @}

  // Returns true if the container is empty.
  bool empty() const { return list_.empty(); }

  // Returns the number of elements in the container.
  size_type size() const { return list_.size(); }

  // Returns the, implementation specific, maximum number of elements the
  // container can hold.
  size_type max_size() const {
    return std::min(list_.max_size(), members_.max_size());
  }

  // Resize the container to contain at most @p sz elements.
  //
  // Note that this method can only make the container smaller not larger
  // (since making it larger would imply inserting duplicate default elements).
  //
  // Returns true if the size of the container is now exactly sz.
  bool resize(size_type sz) {
    while (size() > sz) {
      pop_back();
    }
    return sz == size();
  }

  // Returns a reference to the first element in the container.
  // @{
  reference front() { return list_.front(); }
  const_reference front() const { return list_.front(); }
  // @}

  // Returns a reference to the last element in the container.
  // @{
  reference back() { return list_.back(); }
  const_reference back() const { return list_.back(); }
  // @}

  // Insert an element at the front of the container if the element is not
  // already in the container.
  //
  // @returns true if the element was inserted.
  bool push_front(const value_type& value) {
    if (contains(value))
      return false;
    list_.push_front(value);
    return true;
  }

  // Removes the first element in the container.
  void pop_front() {
    list_.pop_front();
  }

  // Insert an element at the back of the container if the element is not
  // already in the container.
  //
  // @returns true if the element was inserted.
  bool push_back(const value_type& value) {
    if (contains(value))
      return false;
    list_.push_back(value);
    return true;
  }

  // Removes the last element in the container.
  void pop_back() {
    list_.pop_back();
  }

  // Search for a value in the unique list.
  //
  // @param value the value to find.
  // @returns an iterator to the found value or end().
  iterator find(const value_type& value) {
    return std::find(list_.begin(), list_.end(), value);
  }

  // Search for a value in the unique list.
  //
  // @param value the value to find.
  // @returns a const_iterator to the found value or end().
  const_iterator find(const value_type& value) const {
    return std::find(list_.begin(), list_.end(), value);
  }

  // Returns true if @p value is already in the container.
  bool contains(const value_type& value) const {
    return find(value) != end();
  }

  // Inserts @p value into the container at @p position if @p value is not
  // already in the container.
  //
  // @returns an iterator the the inserted element or end().
  iterator insert(iterator position, const value_type& value) {
    if (contains(value))
      return end();
    return list_.insert(position, value);
  }

  // Inserts each value from the input sequence defined by @p first and @p last
  // if the value is not already in the container.
  //
  // @param position the position at which to start inserting.
  // @param first an iterator to the first value to insert.
  // @param last an iterator one past the last value to insert.
  template<typename InputIterator>
  void insert(iterator position, InputIterator first, InputIterator last) {
    while (first != last) {
      iterator insertion_point = insert(position, *first);
      if (insertion_point != end()) {
        position = ++insertion_point;
      }
      ++first;
    }
  }

  // Resets the contents of the the unique list with those in the range
  // [@pfirst, @p last).
  //
  // All items previously in the list are discarded before the new items
  // are inserted.
  //
  // @param first an iterator to the first value to insert.
  // @param last an iterator one past the last value to insert.
  template<typename InputIterator>
  void assign(InputIterator first, InputIterator last) {
    clear();
    insert(end(), first, last);
  }

  // Removes the element at @p position from the container.
  iterator erase(iterator position) {
    return list_.erase(position);
  }

  // Removes all of the elements from @p first to @p last from the container.
  iterator erase(iterator first, iterator last) {
    return list_.erase(first, last);
  }

  // Swaps the contents of this unique container with another unique container.
  void swap(UniqueList& other) {
    list_.swap(other.list_);
  }

  // Removes all elements from the unique container.
  void clear() {
    list_.clear();
  }

  // Sorts the values in the unique container into the order determined by
  // pred.
  template <typename Pred>
  void sort(Pred pred) {
    list_.sort(pred);
  }

  // Sorts the values in the unique container using std::less.
  void sort() {
    list_.sort(std::less<value_type>());
  }

  // Reverses the order of the elements in this unique list.
  void reverse() {
    list_.reverse();
  }

  // Moves elements in range [@p first, @p last) from @p other_container into
  // this unique list, starting at at @p position.
  //
  // Non-unique elements are dropped.
  //
  // @tparam OtherContainerType A container type holding objects of the same
  //     type as this unique list.
  // @param position The position within the container where elements from
  //     @p other_container are inserted.
  // @param other_container A container holding objects of the same type
  //     as this unique list.
  // @param first An iterator specifying the start of the range of objects
  //     in @p other_container to splice.
  // @param last An iterator specifying the end of the range of objects
  //     in @p other_container to splice. Note that the object referred
  //     to by @p last is not spliced.
  template<typename OtherContainerType>
  void splice(iterator position,
              OtherContainerType& other_container,
              typename OtherContainerType::iterator first,
              typename OtherContainerType::iterator last) {
    while (first != last) {
      iterator current = first;
      ++first;
      iterator insertion_point = insert(position, *current);
      if (insertion_point != end()) {
        position = ++insertion_point;
      }
      other_container.erase(current);
    }
  }

  // Moves elements in range [@p first, @p last) from @p other_container into
  // this unique list, starting at at @p position.
  //
  // If @p element is not unique, it is dropped.
  //
  // @tparam OtherContainerType A container type holding objects of the same
  //     type as this unique list.
  // @param position The position within the container where elements from
  //     @p other_container are inserted.
  // @param other_container A container holding objects of the same type
  //     as this unique list.
  // @param element An iterator specifying the object in @p other_container
  //     to be moved.
  template<typename OtherContainerType>
  void splice(iterator position,
              OtherContainerType& other_container,
              typename OtherContainerType::iterator element) {
    typename OtherContainerType::iterator next_element = element;
    ++next_element;
    splice(position, other_container, element, next_element);
  }

  // Moves all of the elements in @p other_container into this unique list,
  // starting at at @p position.
  //
  // Non-unique elements are dropped.
  //
  // @tparam OtherContainerType A container type holding objects of the same
  //     type as this unique list.
  // @param position The position within the container where elements from
  //     @p other_container are inserted.
  // @param other_container A container holding objects of the same type
  //     as this unique list.
  template<typename OtherContainerType>
  void splice(iterator position,
              typename OtherContainerType& other_container) {
    splice(position,
           other_container,
           other_container.begin(),
           other_container.end());
  }

  // Remove the element matching @p value from this unique list.
  void remove(const value_type& value) {
    list_.remove(value);
  }

  // Remove all elements for which @p pred returns true from this unique list.
  //
  // @tparam Predicate The predicate type.
  // @param pred The predicate.
  template<typename Predicate>
  void remove_if(Predicate pred) {
    list_.remove_if(pred);
  }

  // Returns the allocator object used to construct this unique list.
  allocator_type get_allocator() const {
    return list_.get_allocator();
  }

 private:
  // The underlying list.
  list_type list_;
};

}  // namespace common

#endif  // SYZYGY_COMMON_UNIQUE_LIST_H_
