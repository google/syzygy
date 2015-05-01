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
// Defines the members of the ThreadStateBase and ThreadStateManager classes

#include "syzygy/agent/common/thread_state.h"

namespace agent {
namespace common {

ThreadStateBase::ThreadStateBase()
    : thread_handle_(
        ::OpenThread(SYNCHRONIZE, FALSE, ::GetCurrentThreadId())) {
  DCHECK(thread_handle_.IsValid());
  InitializeListHead(&entry_);
}

ThreadStateBase::~ThreadStateBase() {
  DCHECK(IsListEmpty(&entry_));
}

ThreadStateManager::ThreadStateManager() {
  InitializeListHead(&active_items_);
  InitializeListHead(&death_row_items_);
}

ThreadStateManager::~ThreadStateManager() {
  // Destroy all active and death row thread states here. Note that this is
  // racy as hell if other threads are active, but it's the caller's
  // responsibility to ensure that's not the case.

  // Attempt an orderly deletion of items of the death row.
  Scavenge();

  // Note that we don't hold lock_ for these operations, as the destructor
  // has to be the only member of the party at this point.
  if (!IsListEmpty(&death_row_items_)) {
    // This will happen if the items have been marked for death, but their
    // threads are still active.
    LOG(WARNING) << "Active death row items at manager destruction.";

    DeleteItems(&death_row_items_);
  }

  if (!IsListEmpty(&active_items_)) {
    // This can and will happen if other threads in the process have been
    // terminated, as that'll orphan their thread states.
    LOG(WARNING) << "Active thread states at manager destruction.";

    DeleteItems(&active_items_);
  }

  // If either of these asserts fire, then there are active threads in the
  // process that are still interacting with the manager. This is obviously
  // very bad, as the manager is about to wink out of existence.
  DCHECK(IsListEmpty(&active_items_));
  DCHECK(IsListEmpty(&death_row_items_));
}

void ThreadStateManager::Register(ThreadStateBase* item) {
  DCHECK(item != NULL);
  DCHECK(IsListEmpty(&item->entry_));
  base::AutoLock auto_lock(lock_);
  InsertTailList(&active_items_, &item->entry_);
}

void ThreadStateManager::Unregister(ThreadStateBase* item) {
  DCHECK(item != NULL);
  base::AutoLock auto_lock(lock_);
  RemoveEntryList(&item->entry_);
  InitializeListHead(&item->entry_);
}

void ThreadStateManager::MarkForDeath(ThreadStateBase* item) {
  DCHECK(item != NULL);

  {
    base::AutoLock auto_lock(lock_);

    // Make sure the item we're marking is on the active or death row lists.
    DCHECK(IsNodeOnList(&active_items_, &item->entry_) ||
           IsNodeOnList(&death_row_items_, &item->entry_));

    // Pull it out of the list it's on, this'll preserve it over the scavenge
    // below, in the unlikely case that the item is being marked from another
    // thread than it's own.
    RemoveEntryList(&item->entry_);
  }

  // Use this opportunity to scavenge existing thread states on death row.
  Scavenge();

  // Mark item for death, for later scavenging.
  {
    base::AutoLock auto_lock(lock_);

    InsertHeadList(&death_row_items_, &item->entry_);
  }
}

bool ThreadStateManager::Scavenge() {
  // We'll store the list of scavenged items here.
  LIST_ENTRY dead_items;
  InitializeListHead(&dead_items);
  bool has_more_items = false;

  // Acquire the lock when interacting with the internal data.
  {
    base::AutoLock auto_lock(lock_);

    // Put all of the death row items belonging
    // to dead threads into dead_items.
    GatherDeadItemsUnlocked(&dead_items);

    // Return whether or not the thread state manager is no longer holding
    // any items.
    has_more_items =
        !IsListEmpty(&active_items_) || !IsListEmpty(&death_row_items_);
  }

  // We can delete any dead items we found outside of the lock.
  DeleteItems(&dead_items);
  DCHECK(IsListEmpty(&dead_items));

  return has_more_items;
}

void ThreadStateManager::GatherDeadItemsUnlocked(LIST_ENTRY* dead_items) {
  DCHECK(dead_items != NULL);
  DCHECK(IsListEmpty(dead_items));
  lock_.AssertAcquired();

  // Return if the death row items list is empty.
  if (IsListEmpty(&death_row_items_))
    return;

  // Walk the death row items list, looking for items owned by dead threads.
  ThreadStateBase* item =
      CONTAINING_RECORD(death_row_items_.Flink, ThreadStateBase, entry_);
  while (item != NULL) {
    ThreadStateBase* next_item = NULL;
    if (item->entry_.Flink != &death_row_items_) {
      next_item =
          CONTAINING_RECORD(item->entry_.Flink, ThreadStateBase, entry_);
    }

    // Move the item to the dead_items list if the associated thread is dead.
    if (IsThreadDead(item)) {
      RemoveEntryList(&item->entry_);
      InsertTailList(dead_items, &item->entry_);
    }

    item = next_item;
  }
}

bool ThreadStateManager::IsThreadDead(ThreadStateBase* item) {
  DCHECK(item != NULL);
  return ::WaitForSingleObject(item->thread_handle_.Get(), 0) == WAIT_OBJECT_0;
}

void ThreadStateManager::DeleteItems(LIST_ENTRY* items) {
  DCHECK(items != NULL);
  // Let's delete all entries in items.
  while (!IsListEmpty(items)) {
    ThreadStateBase* item =
        CONTAINING_RECORD(items->Flink, ThreadStateBase, entry_);
    RemoveHeadList(items);
    InitializeListHead(&item->entry_);
    delete item;
  }
}

}  // namespace common
}  // namespace agent
