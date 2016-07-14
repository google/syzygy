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

#include <utility>

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
// Note that since pushing/popping the quarantine are not atomic operations, the
// size/count can become negative in transition, hence the need to have them as
// signed integer (only their eventual consistency is guaranteed).
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
  SSIZE_T size() const {
    lock_.AssertAcquired();
    return size_;
  }

  // @returns the count.
  SSIZE_T count() const {
    lock_.AssertAcquired();
    return count_;
  }

  // Increments the size and count.
  // @param size_delta The delta by which the size is incremented.
  // @param count_delta The delta by which the count is incremented.
  // @returns the new size.
  SSIZE_T Increment(SSIZE_T size_delta, SSIZE_T count_delta) {
    lock_.AssertAcquired();
    size_ += size_delta;
    count_ += count_delta;
    return size_;
  }

  // Decrements the size and count.
  // @param size_delta The delta by which the size is decremented.
  // @param count_delta The delta by which the count is decremented.
  // @returns the new size.
  SSIZE_T Decrement(SSIZE_T size_delta, SSIZE_T count_delta) {
    lock_.AssertAcquired();
    size_ -= size_delta;
    count_ -= count_delta;
    return size_;
  }

 private:
  // The current size of the quarantine.
  SSIZE_T size_;
  // The number of elements in the quarantine.
  SSIZE_T count_;
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
        size_functor_(),
        overbudget_size_(0) {}

  // Constructor. Initially the quarantine has unlimited capacity.
  // @param size_functor The size functor to be used. This will be copied
  //     into the classes member size functor.
  explicit SizeLimitedQuarantineImpl(const SizeFunctor& size_functor)
      : max_object_size_(kUnboundedSize),
        max_quarantine_size_(kUnboundedSize),
        size_functor_(size_functor),
        overbudget_size_(0) {}

  // Constructor. Takes the quarantine capacity.
  // @param max_quarantine_size The capacity of the quarantine.
  explicit SizeLimitedQuarantineImpl(size_t max_quarantine_size)
      : max_object_size_(kUnboundedSize),
        max_quarantine_size_(max_quarantine_size),
        size_functor_(),
        overbudget_size_(0) {}

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
  // return a stale value. It is only used in tests.
  size_t GetSizeForTesting() {
    ScopedQuarantineSizeCountLock size_count_lock(size_count_);
    return size_count_.size();
  }

  // @returns the current overbudget size.
  size_t GetOverbudgetSizeForTesting() const { return overbudget_size_; }

  // Sets the overbudget size by which the quarantine is allowed to go over and
  // enables hysteresis by defining color regions.  Note that once the size is
  // set, it cannot be changed unless the hysteresis is removed first by setting
  // the size to 0. It is also illegal to set the size to 0 if it's already at
  // that value.
  // @param overbudget_size The overbudget size. This is capped to half of
  //     the maximum size of the quarantine and must be at least 1024 bytes. If
  //     0, this removes the hysteresis.
  void SetOverbudgetSize(size_t overbudget_size);

  // Returns the color of the quarantine, depending on the size. See note in
  // implementation about the raciness of the function.
  // @param size The size that is used to calculate the color.
  // @returns the color of the quarantine.
  TrimColor GetQuarantineColor(size_t size) const;

  // Returns the maximum size of a certain color. Used only in testing.
  // @param color The color for which the size is queried.
  // @returns the size.
  size_t GetMaxSizeForColorForTesting(TrimColor color) const;

  // @name QuarantineInterface implementation.
  // @note that GetCountForTest could be racing with a push/pop operation and
  // return a stale value. It is only used in in tests.
  // @{
  virtual PushResult Push(const Object& object);
  virtual PopResult Pop(Object* object);
  virtual void Empty(ObjectVector* objects);
  virtual size_t GetCountForTesting();
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

  // The size by which the quarantine is allowed to go over until it has to be
  // synchronously trimmed. This is atomically accessed. Since it is not behind
  // a lock, when modified, this could potentially lead to transitions between
  // colors being missed. The implementation takes this factor into
  // consideration.
  base::subtle::AtomicWord overbudget_size_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SizeLimitedQuarantineImpl);
};

}  // namespace quarantines
}  // namespace asan
}  // namespace agent

#include "syzygy/agent/asan/quarantines/size_limited_quarantine_impl.h"

#endif  // SYZYGY_AGENT_ASAN_QUARANTINES_SIZE_LIMITED_QUARANTINE_H_
