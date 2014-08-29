// Copyright 2014 Google Inc. All Rights Reserved.
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
// An implementation of a size-limited quarantine. This encapsulates the
// logic for maintaining a size invariant over the items in a quarantine.

#ifndef SYZYGY_AGENT_ASAN_QUARANTINES_SIZE_LIMITED_QUARANTINE_H_
#define SYZYGY_AGENT_ASAN_QUARANTINES_SIZE_LIMITED_QUARANTINE_H_

#include "syzygy/agent/asan/quarantine.h"

namespace agent {
namespace asan {
namespace quarantines {

// A partial implementation of a size-limited quarantine. This quarantine
// obeys a simple invariant: the sum of object weights within it must be
// less than a certain threshold, and all objects within it must be smaller
// than another given threshold.
//
// Provides implementations of QuarantineInterface Push/Pop/Empty methods.
// Expects the derived class to provide implementations for a few methods:
//
//   bool PushImpl(const ObjectType& object);
//   void PopImpl(ObjectType* object);
//   void EmptyImpl(ObjectVector* object);
//
// Calculates the sizes of objects using the provided SizeFunctor. This
// must satisfy the following interface:
//
// struct SizeFunctor {
//   size_t operator()(const ObjectType& object);
// };
//
// @tparam ObjectType The type of object stored in the quarantine.
// @tparam SizeFunctorType The size functor that will be used to extract
//     a size from an object.
template<typename ObjectType, typename SizeFunctorType>
class SizeLimitedQuarantineImpl : public QuarantineInterface<ObjectType> {
 public:
  typedef SizeFunctorType SizeFunctor;

  static const size_t kUnboundedSize = ~0;

  // Constructor. Initially the quarantine has unlimited capacity.
  SizeLimitedQuarantineImpl()
      : max_object_size_(kUnboundedSize),
        max_quarantine_size_(kUnboundedSize),
        size_(0),
        count_(0),
        size_functor_() {
  }

  // Constructor. Initially the quarantine has unlimited capacity.
  // @param size_functor The size functor to be used. This will be copied
  //     into the classes member size functor.
  explicit SizeLimitedQuarantineImpl(const SizeFunctor& size_functor)
      : max_object_size_(kUnboundedSize),
        max_quarantine_size_(kUnboundedSize),
        size_(0),
        count_(0),
        size_functor_(size_functor) {
  }

  // Virtual destructor.
  virtual ~SizeLimitedQuarantineImpl() { }

  // Sets the maximum object size. This only gates the entry of future
  // objects to 'Push', and does not invalidate overly objects already in
  // the quarantine.
  // @param max_object_size The maximum size of any single object in the
  //     quarantine. Use kUnboundedSize for unlimited (no max).
  void set_max_object_size(size_t max_object_size) {
    max_object_size_ = max_object_size;
  }

  // Sets the maximum quarantine size. This may cause the quarantine
  // invariant to be immediately invalidated, requiring calls to 'Pop'.
  // @param max_quarantine_size The maximum size of the entire quarantine.
  //     Use kUnboundedSize for unlimited (no max).
  void set_max_quarantine_size(size_t max_quarantine_size) {
    max_quarantine_size_ = max_quarantine_size;
  }

  // @returns the maximum object size.
  size_t max_object_size() const { return max_object_size_; }

  // @returns the maximum quarantine size.
  size_t max_quarantine_size() const { return max_quarantine_size_; }

  // @returns the current size of the quarantine.
  size_t size() const { return size_; }

  // @name QuarantineInterface implementation.
  // @{
  virtual bool Push(const Object& object);
  virtual bool Pop(Object* object);
  virtual void Empty(ObjectVector* objects);
  virtual size_t GetCount();
  // @}

 protected:
  // @name SizeLimitedQuarantine interface.
  // @{
  virtual bool PushImpl(const Object& object) = 0;
  virtual void PopImpl(Object* object) = 0;
  virtual void EmptyImpl(ObjectVector* objects) = 0;
  // @}

  // Parameters controlling the quarantine invariant.
  size_t max_object_size_;
  size_t max_quarantine_size_;

  // The current size of the quarantine.
  size_t size_;

  // The number of elements in the quarantine.
  size_t count_;

  // The size functor.
  SizeFunctor size_functor_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SizeLimitedQuarantineImpl);
};

}  // namespace quarantines
}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/quarantines/size_limited_quarantine_impl.h"

#endif  // SYZYGY_AGENT_ASAN_QUARANTINES_SIZE_LIMITED_QUARANTINE_H_
