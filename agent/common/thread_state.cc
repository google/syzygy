// Copyright 2012 Google Inc.
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
    : thread_handle_(::OpenThread(SYNCHRONIZE, FALSE, ::GetCurrentThreadId())) {
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
  bool has_leaked_items = false;
  Scavenge(NULL, &has_leaked_items);
  if (has_leaked_items)
    LOG(WARNING) << "Leaking thread state items.";
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
  Scavenge(item, NULL);
}

void ThreadStateManager::Scavenge(ThreadStateBase* item, bool* has_more_items) {
  // We'll store the list of scavenged items here.
  LIST_ENTRY dead_items;
  InitializeListHead(&dead_items);

  // Acquire the lock when interacting with the internal data.
  {
    base::AutoLock auto_lock(lock_);

    // Put all of the death row items belong to dead threads into dead_items.
    GatherDeadItemsUnlocked(&dead_items);

    // If there's an item to mark for death, do so. We do this after gathering
    // the dead items because the item in question presumably belongs to the
    // current thread and so could never be gathered.
    if (item != NULL) {
      RemoveEntryList(&item->entry_);
      InsertHeadList(&death_row_items_, &item->entry_);
    }

    // Return whether or not the thread state manager is no longer holding
    // any items.
    if (has_more_items != NULL) {
      *has_more_items =
          !IsListEmpty(&active_items_) || !IsListEmpty(&death_row_items_);
    }
  }

  // We can delete any dead items we found outside of the lock.
  DeleteDeadItems(&dead_items);
  DCHECK(IsListEmpty(&dead_items));
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
  return ::WaitForSingleObject(item->thread_handle_, 0)  == WAIT_OBJECT_0;
}

void ThreadStateManager::DeleteDeadItems(LIST_ENTRY* dead_items) {
  DCHECK(dead_items != NULL);
  // Ok, let's kill any entries we scavenged.
  while (!IsListEmpty(dead_items)) {
    ThreadStateBase* item =
        CONTAINING_RECORD(dead_items->Flink, ThreadStateBase, entry_);
    RemoveHeadList(dead_items);
    InitializeListHead(&item->entry_);
    delete item;
  }
}

}  // namespace common
}  // namespace agent
