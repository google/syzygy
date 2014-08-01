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

  // Places an allocation in the quarantine. This routine must be thread-safe.
  // @param The object to place in the quarantine.
  // @returns true if the has been accepted by and placed in the quarantine,
  //     and false if its entry has been refused.
  virtual bool Push(const Object& object) = 0;

  // Potentially removes an object from the quarantine to maintain the
  // invariant. This routine must be thread-safe.
  // @param object Is filled in with a copy of the removed object.
  // @returns true if an object was removed, false otherwise. If this returns
  //     false then the cache invariant is satisfied.
  virtual bool Pop(Object* object) = 0;

  // Removes all objects from the quarantine, placing them in the provided
  // vector. This routine must be thread-safe.
  virtual void Empty(ObjectVector* objects) = 0;

  // The number of objects currently in the quarantine.
  // @returns the number of objects in the quarantine.
  virtual size_t GetCount() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuarantineInterface);
};

// Quarantines in ASAN are typically storing blocks, represented by the address
// of their allocation.
struct BlockHeader;  // Forward declaration.
typedef QuarantineInterface<BlockHeader*> BlockQuarantineInterface;

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_QUARANTINE_H_
