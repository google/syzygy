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
// Declares a quarantine, which is used to temporarily house allocations after
// they've been freed, permitting use-after-frees to be detected.

#ifndef SYZYGY_AGENT_ASAN_QUARANTINE_H_
#define SYZYGY_AGENT_ASAN_QUARANTINE_H_

#include <vector>

#include "base/logging.h"

namespace agent {
namespace asan {

// Specifies the color of the quarantine, depending on its size. YELLOW means
// that we are below the maximum size whereas BLACK means we are way overbudget.
// We also have two other colors, GREEN and RED, that are used to add
// hysteresis. Basically, the color order is as follows:
//     GREEN -> YELLOW -> RED -> BLACK
// Having these multiple colors allows for trimming the quarantine at different
// paces, depending on urgency (urgent trimming is done synchronously on the
// critical path whereas non-urgent is done asynchronously in a background
// thread). For more information about the colors, see implementation of
// GetQuarantineColor.
enum TrimColor { GREEN, YELLOW, RED, BLACK };

// Used to indicate whether the quarantine must be trimmed synchronously, be
// scheduled for trimming by the background thread (asynchronously) or both.
using TrimStatus = uint32_t;
enum TrimStatusBits : uint32_t {
  TRIM_NOT_REQUIRED = 0,
  ASYNC_TRIM_REQUIRED = 1 << 0,
  SYNC_TRIM_REQUIRED = 1 << 1
};

// Type returned by Push. It returns whether the push was successful or not and
// whether the quarantine requires trimming (either sync and/or async).
struct PushResult {
  bool push_successful;
  TrimStatus trim_status;
};

// Type returned by Pop. It returns whether the pop was successful or not and
// the color of the quarantine post-pop.
struct PopResult {
  bool pop_successful;
  TrimColor trim_color;
};

// The interface that quarantines must satisfy. They store literal copies of
// objects of type |ObjectType|.
//
// Placing objects in the quarantine and removing them from it are factored
// out as two separate steps. Thus it is possible for a quarantine invariant
// to be invalidated by a call to 'Push', which won't be restored until
// sufficient calls to 'Pop' have been made.
//
// This has been templated on the object type to allow easier unittesting.
//
// @tparam ObjectType The type of object stored by the quarantine.
template<typename ObjectType>
class QuarantineInterface {
 public:
  typedef ObjectType Object;
  typedef std::vector<Object> ObjectVector;

  // Constructor.
  QuarantineInterface() { }

  // Virtual destructor.
  virtual ~QuarantineInterface() { }

  // Places an allocation in the quarantine. This routine must be called under
  // Lock.
  // @param The object to place in the quarantine.
  // @returns a PushResult.
  virtual PushResult Push(const Object& object) = 0;

  // Potentially removes an object from the quarantine to maintain the
  // invariant. This routine must be thread-safe, and implement its own locking.
  // @param object Is filled in with a copy of the removed object.
  // @returns a PopResult.
  virtual PopResult Pop(Object* object) = 0;

  // Removes all objects from the quarantine, placing them in the provided
  // vector. This routine must be thread-safe, and implement its own locking.
  virtual void Empty(ObjectVector* objects) = 0;

  // The number of objects currently in the quarantine. Only used in testing, as
  // the implementation is racy.
  // @returns the number of objects in the quarantine.
  virtual size_t GetCountForTesting() = 0;

  // An automatic quarantine lock.
  //
  // This class is nested into the QuarantineInterface class to avoid a
  // complicated template definition. It also avoids exposing the Lock/Unlock
  // functions.
  class AutoQuarantineLock {
   public:
    // Constructor. Automatically lock the quarantine.
    AutoQuarantineLock(QuarantineInterface* quarantine,
                       const ObjectType& object)
        : quarantine_(quarantine) {
      DCHECK_NE(reinterpret_cast<QuarantineInterface*>(NULL), quarantine_);
      lock_index_ = quarantine_->GetLockId(object);
      quarantine_->Lock(lock_index_);
    }

    // Destructor. Automatically unlock the quarantine.
    ~AutoQuarantineLock() {
      quarantine_->Unlock(lock_index_);
    }

   private:
    // The bucket to lock in the quarantine.
    size_t lock_index_;

    // The quarantine to lock.
    QuarantineInterface* quarantine_;

    DISALLOW_COPY_AND_ASSIGN(AutoQuarantineLock);
  };

 private:
  // Get the lock ID associated with a given object in the quarantine. This is
  // useful in the case where there's several buckets in the quarantine.
  // @param object The object for which we want to retrieve the lock ID
  //     associated with it.
  // @returns the lock ID associated with this object.
  virtual size_t GetLockId(const Object& object) = 0;

  // Lock the quarantine.
  // @param id The bucket to lock, ignored if the quarantine isn't sharded.
  virtual void Lock(size_t id) = 0;

  // Unlock the quarantine.
  // @param id The bucket to lock, ignored if the quarantine isn't sharded.
  virtual void Unlock(size_t id) = 0;

  DISALLOW_COPY_AND_ASSIGN(QuarantineInterface);
};

// Quarantines in Asan are typically storing blocks. Here they are represented
// by a CompactBlockInfo, which contains information that the quarantine
// frequently accesses.
struct CompactBlockInfo;  // Forward declaration.
typedef QuarantineInterface<CompactBlockInfo> BlockQuarantineInterface;

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_QUARANTINE_H_
