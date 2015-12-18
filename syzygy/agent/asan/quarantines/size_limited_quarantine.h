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

#include "base/atomicops.h"
#include "base/synchronization/lock.h"
#include "syzygy/agent/asan/quarantine.h"

namespace agent {
namespace asan {
namespace quarantines {

// Provides both the size of the quarantine and the number of elements it
// contains. Both of these are accessed behind a lock, to ensure their
// consistency. Hence, the lock must be acquired (by calling Lock) before any
// other operation is performed. The lock should be returned (by calling Unlock)
// as soon as possible to minimize the locked time.
class QuarantineSizeCount {
 public:
  // Default constructor that sets the size and count to 0.
  QuarantineSizeCount() : size_(0), count_(0) {}

  // Must be called before any other operation to acquire the lock.
  void Lock() { lock_.Acquire(); }

  // Releases the lock.
  void Unlock() {
    lock_.AssertAcquired();
    lock_.Release();
  }

  // @returns the size.
  int32 size() const {
    lock_.AssertAcquired();
    return size_;
  }

  // @returns the count.
  int32 count() const {
    lock_.AssertAcquired();
    return count_;
  }

  // Increments the size and count (accepts negative values for decrementing).
  // @param size_delta The delta by which the size is incremented.
  // @param count_delta The delta by which the count is incremented.
  void Increment(int32 size_delta, int32 count_delta) {
    lock_.AssertAcquired();
    size_ += size_delta;
    count_ += count_delta;
  }

 private:
  // The current size of the quarantine.
  int32 size_;
  // The number of elements in the quarantine.
  int32 count_;
  // Single lock that's used for both |size_| and |count_|.
  base::Lock lock_;
};

// An automatic lock on QuarantineSizeCount.
class ScopedQuarantineSizeCountLock {
 public:
  // Constructor. Automatically lock the quarantine.
  explicit ScopedQuarantineSizeCountLock(QuarantineSizeCount& size_count)
      : size_count_(size_count) {
    size_count_.Lock();
  }

  // Destructor. Automatically unlock the quarantine.
  ~ScopedQuarantineSizeCountLock() { size_count_.Unlock(); }

 private:
  // The QuarantineSizeCount that this holds.
  QuarantineSizeCount& size_count_;

  DISALLOW_COPY_AND_ASSIGN(ScopedQuarantineSizeCountLock);
};

// A partial implementation of a size-limited quarantine. This quarantine
// obeys a simple invariant: the sum of object weights within it must be
// less than a certain threshold, and all objects within it must be smaller
// than another given threshold.
//
// Provides implementations of QuarantineInterface Push/Pop/Empty methods.
// Expects the derived class to provide implementations for a few methods:
//
//   bool PushImpl(const ObjectType& object);
//   bool PopImpl(ObjectType* object);
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

  static const size_t kUnboundedSize = SIZE_MAX;

  // Constructor. Initially the quarantine has unlimited capacity.
  SizeLimitedQuarantineImpl()
      : max_object_size_(kUnboundedSize),
        max_quarantine_size_(kUnboundedSize),
        size_functor_() {
  }

  // Constructor. Initially the quarantine has unlimited capacity.
  // @param size_functor The size functor to be used. This will be copied
  //     into the classes member size functor.
  explicit SizeLimitedQuarantineImpl(const SizeFunctor& size_functor)
      : max_object_size_(kUnboundedSize),
        max_quarantine_size_(kUnboundedSize),
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
  // @note that this function could be racing with a push/pop operation and
  // return a stale value. It should only be used when this is acceptable (in
  // tests for example).
  size_t size() {
    ScopedQuarantineSizeCountLock size_count_lock(size_count_);
    return size_count_.size();
  }

  // @name QuarantineInterface implementation.
  // @note that GetCount could be racing with a push/pop operation and return a
  // stale value. It should only be used when this is acceptable (in tests for
  // example).
  // @{
  virtual bool Push(const Object& object);
  virtual bool Pop(Object* object);
  virtual void Empty(ObjectVector* objects);
  virtual size_t GetCount();
  virtual size_t GetLockId(const Object& object);
  virtual void Lock(size_t id);
  virtual void Unlock(size_t id);
  // @}

 protected:
  // @name SizeLimitedQuarantine interface.
  // @{
  virtual bool PushImpl(const Object& object) = 0;
  virtual bool PopImpl(Object* object) = 0;
  virtual void EmptyImpl(ObjectVector* objects) = 0;
  virtual size_t GetLockIdImpl(const Object& object) = 0;
  virtual void LockImpl(size_t id) = 0;
  virtual void UnlockImpl(size_t id) = 0;
  // @}

  // Parameters controlling the quarantine invariant.
  size_t max_object_size_;
  size_t max_quarantine_size_;

  QuarantineSizeCount size_count_;

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
