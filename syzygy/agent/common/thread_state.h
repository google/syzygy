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
// Defines the ThreadStateBase and ThreadStateManager classes, which assists in
// tracking and properly scavenging thread local resources owned by an agent
// DLL as threads attach and detach from instrumented modules.

#ifndef SYZYGY_AGENT_COMMON_THREAD_STATE_H_
#define SYZYGY_AGENT_COMMON_THREAD_STATE_H_

#include "base/synchronization/lock.h"
#include "base/win/scoped_handle.h"
#include "syzygy/agent/common/dlist.h"

namespace agent {
namespace common {

// An abstract base class from which agent specific thread state objects
// should be derived. This object maintains a handle to the thread on which
// it was created. It is therefore expected that the thread state object will
// be created by the thread on which it will be used.
class ThreadStateBase {
 public:
  // Initialize a ThreadStateBase instance.
  ThreadStateBase();

  // A virtual destructor to allow sub-classes to be safely deleted by the
  // ThreadStateManager.
  virtual ~ThreadStateBase() = 0;

 protected:
  friend class ThreadStateManager;

  // The handle of the owning thread, used to scavenge thread data.
  base::win::ScopedHandle thread_handle_;

  // The entry linking us into the manager's active_items_ or death_row_ lists.
  LIST_ENTRY entry_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ThreadStateBase);
};

// A thread-safe class to manage the thread local state used by an agent.
class ThreadStateManager {
 public:
  // Initialize a ThreadStateManager instance.
  ThreadStateManager();

  // Destroys a ThreadStateManager instance.
  ~ThreadStateManager();

  // Insert @p item into the list of active items.
  void Register(ThreadStateBase* item);

  // Forcibly removes a thread state @p item from the active or death-row list,
  // as appropriate.
  void Unregister(ThreadStateBase* item);

  // Transfer @p item from the list of active items to the death row list. This
  // does not delete @p item immediately if it's called on @p items' own
  // thread.
  void MarkForDeath(ThreadStateBase* item);

 protected:
  // A helper method which gathers up any dead items from the death row list.
  // @returns true iff there are any items still being managed by this
  //     ThreadStateManager instance upon this functions return.
  bool Scavenge();

  // Gathers all items which have been marked for death whose owning threads
  // have terminated into @p dead_items. These items can subsequently be
  // deleted using the Delete() method.
  void GatherDeadItemsUnlocked(LIST_ENTRY* dead_items);

  // Deletes (using the delete operator) each item in @p items.
  static void DeleteItems(LIST_ENTRY* items);

  // Returns true if the thread which owns @p item has terminated.
  static bool IsThreadDead(ThreadStateBase* item);

  // A lock protecting access to the lists of active and death_row entries.
  base::Lock lock_;

  // A doubly-linked list of all thread local data items not yet marked for
  // death. Accessed under lock_.
  LIST_ENTRY active_items_;

  // A doubly-linked list of all thread local data items currently marked for
  // death. Accessed under lock_.
  LIST_ENTRY death_row_items_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ThreadStateManager);
};

}  // namespace common
}  // namespace agent

#endif  // SYZYGY_AGENT_COMMON_THREAD_STATE_H_
