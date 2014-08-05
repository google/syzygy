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

#include "syzygy/agent/asan/heap_managers/block_heap_manager.h"

#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/heaps/simple_block_heap.h"
#include "syzygy/agent/asan/heaps/win_heap.h"
#include "syzygy/common/asan_parameters.h"

namespace agent {
namespace asan {
namespace heap_managers {

namespace {

typedef HeapManagerInterface::HeapId HeapId;

}  // namespace

BlockHeapManager::BlockHeapManager(AsanLogger* logger)
    : stack_cache_(logger) {
  SetDefaultAsanParameters(&parameters_);
  PropagateParameters();
}

BlockHeapManager::~BlockHeapManager() {
  shared_quarantine_.set_max_quarantine_size(0);
  TrimQuarantine(&shared_quarantine_);
  base::AutoLock lock(lock_);
  // Delete all the heaps.
  HeapQuarantineMap::iterator iter_heaps = heaps_.begin();
  for (; iter_heaps != heaps_.end(); ++iter_heaps)
    DestroyHeapUnlocked(iter_heaps->first, iter_heaps->second);
  heaps_.clear();
}

HeapId BlockHeapManager::CreateHeap() {
  // Creates a simple heap and returns it to the user.

  // Creates the underlying heap used by this heap.
  HeapInterface* win_heap = new heaps::WinHeap();
  // Creates the heap.
  BlockHeapInterface* heap = new heaps::SimpleBlockHeap(win_heap);

  base::AutoLock lock(lock_);
  underlying_heaps_map_.insert(std::make_pair(heap, win_heap));
  heaps_.insert(std::make_pair(heap, &shared_quarantine_));

  return reinterpret_cast<HeapId>(heap);
}

bool BlockHeapManager::DestroyHeap(HeapId heap_id) {
  base::AutoLock lock(lock_);
  HeapQuarantineMap::iterator iter = heaps_.find(
      reinterpret_cast<BlockHeapInterface*>(heap_id));
  // We should always be able to retrieve a heap that we previously passed to
  // the user.
  CHECK(iter != heaps_.end());
  // Destroy the heap and flush its quarantine.
  DestroyHeapUnlocked(iter->first, iter->second);

  heaps_.erase(iter);
  return true;
}

void* BlockHeapManager::Allocate(HeapId heap_id, size_t bytes) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);
  BlockLayout block_layout = {};
  void* ptr = reinterpret_cast<BlockHeapInterface*>(heap_id)->AllocateBlock(
      bytes,
      0,
      parameters_.trailer_padding_size + sizeof(BlockTrailer),
      &block_layout);
  DCHECK_NE(reinterpret_cast<void*>(NULL), ptr);
  DCHECK_EQ(0u, reinterpret_cast<size_t>(ptr) % kShadowRatio);
  BlockInfo block = {};
  BlockInitialize(block_layout, ptr, false, &block);

  // Capture the current stack. InitFromStack is inlined to preserve the
  // greatest number of stack frames.
  StackCapture stack;
  stack.InitFromStack();
  block.header->alloc_stack = stack_cache_.SaveStackTrace(stack);
  block.header->free_stack = NULL;

  block.trailer->heap_id = heap_id;

  BlockSetChecksum(block);
  Shadow::PoisonAllocatedBlock(block);

  return block.body;
}

bool BlockHeapManager::Free(HeapId heap_id, void* alloc) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);

  BlockHeader* header = BlockGetHeaderFromBody(alloc);
  BlockHeapInterface* heap = reinterpret_cast<BlockHeapInterface*>(heap_id);
  if (header == NULL) {
    // TODO(sebmarchand): Report a heap error.
    return false;
  }

  BlockInfo block_info = {};
  if (IsBlockCorrupt(reinterpret_cast<uint8*>(header), &block_info)) {
    // TODO(sebmarchand): Report that the block is corrupt.
    return false;
  }

  ShardedBlockQuarantine* quarantine = NULL;
  {
    base::AutoLock lock(lock_);
    HeapQuarantineMap::iterator iter_heap = heaps_.find(
        reinterpret_cast<BlockHeapInterface*>(heap_id));
    // We should always be able to retrieve a heap that we previously passed to
    // the user.
    CHECK(iter_heap != heaps_.end());

    DCHECK_NE(reinterpret_cast<ShardedBlockQuarantine*>(NULL),
              iter_heap->second);
    quarantine = iter_heap->second;
  }

  if (quarantine->Push(header)) {
    StackCapture stack;
    stack.InitFromStack();
    header->free_stack = stack_cache_.SaveStackTrace(stack);
    block_info.trailer->free_ticks = ::GetTickCount();
    block_info.trailer->free_tid = ::GetCurrentThreadId();

    header->state = QUARANTINED_BLOCK;

    // Poison the released alloc (marked as freed) and quarantine the block.
    // Note that the original data is left intact. This may make it easier
    // to debug a crash report/dump on access to a quarantined block.
    Shadow::MarkAsFreed(block_info.body, block_info.body_size);
    BlockSetChecksum(block_info);
    TrimQuarantine(quarantine);
  } else {
    return FreeBlock(header);
  }

  return true;
}

size_t BlockHeapManager::Size(HeapId heap_id, void* alloc) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);
  BlockHeader* header = BlockGetHeaderFromBody(alloc);
  if (header == NULL)
    return 0;
  return header->body_size;
}

void BlockHeapManager::Lock(HeapId heap_id) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);
  reinterpret_cast<HeapInterface*>(heap_id)->Lock();
}

void BlockHeapManager::Unlock(HeapId heap_id) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);
  reinterpret_cast<HeapInterface*>(heap_id)->Unlock();
}

void BlockHeapManager::set_parameters(
    const common::AsanParameters& parameters) {
  {
    base::AutoLock lock(lock_);
    parameters_ = parameters;
  }
  // Releases the lock before propagating the parameters.
  PropagateParameters();
}

void BlockHeapManager::PropagateParameters() {
  size_t quarantine_size = shared_quarantine_.max_quarantine_size();
  shared_quarantine_.set_max_quarantine_size(parameters_.quarantine_size);
  shared_quarantine_.set_max_object_size(parameters_.quarantine_block_size);

  // Trim the quarantine if its maximum size has decreased.
  if (quarantine_size > parameters_.quarantine_size)
    TrimQuarantine(&shared_quarantine_);

  // TODO(chrisha|sebmarchand): Clean up existing blocks that exceed the
  //     maximum block size? This will require an entirely new TrimQuarantine
  //     function. Since this is never changed at runtime except in our
  //     unittests, this is not clearly useful.
}

bool BlockHeapManager::DestroyHeapUnlocked(BlockHeapInterface* heap,
                                           ShardedBlockQuarantine* quarantine) {
  DCHECK_NE(reinterpret_cast<BlockHeapInterface*>(NULL), heap);
  DCHECK_NE(reinterpret_cast<ShardedBlockQuarantine*>(NULL), quarantine);

  // Starts by removing all the block from this heap from the quarantine.

  ShardedBlockQuarantine::ObjectVector blocks_vec;

  // We'll keep the blocks that don't belong to this heap in a temporary list.
  // While this isn't optimal in terms of performance, destroying a heap isn't a
  // common operation.
  // TODO(sebmarchand): Add a version of the ShardedBlockQuarantine::Empty
  //     method that accepts a functor to filter the blocks to remove.
  ShardedBlockQuarantine::ObjectVector blocks_to_reinsert;
  quarantine->Empty(&blocks_vec);
  ShardedBlockQuarantine::ObjectVector::iterator iter_block =
      blocks_vec.begin();

  for (; iter_block != blocks_vec.end(); ++iter_block) {
    // TODO(sebmarchand): Report that the block is corrupt if this call
    //     returns false.
    BlockInfo block_info = {};
    if (!Shadow::BlockInfoFromShadow(*iter_block, &block_info)) {
      // TODO(sebmarchand): Report that the heap is corrupt.
      return false;
    }
    if (reinterpret_cast<BlockHeapInterface*>(block_info.trailer->heap_id) ==
        heap) {
      FreeBlock(*iter_block);
    } else {
      blocks_to_reinsert.push_back(*iter_block);
    }
  }
  // Restore the blocks that don't belong to this quarantine.
  iter_block = blocks_to_reinsert.begin();
  for (; iter_block != blocks_to_reinsert.end(); ++iter_block)
    quarantine->Push(*iter_block);

  UnderlyingHeapMap::iterator iter = underlying_heaps_map_.find(heap);
  DCHECK(iter != underlying_heaps_map_.end());
  DCHECK_NE(reinterpret_cast<HeapInterface*>(NULL), iter->second);
  delete iter->second;
  underlying_heaps_map_.erase(iter);
  delete heap;
  return true;
}

void BlockHeapManager::TrimQuarantine(ShardedBlockQuarantine* quarantine) {
  DCHECK_NE(reinterpret_cast<ShardedBlockQuarantine*>(NULL), quarantine);
  // Trim the quarantine to the new maximum size if it's not zero, empty it
  // otherwise.
  if (quarantine->max_quarantine_size() != 0) {
    BlockHeader* block_to_free = NULL;
    while (quarantine->Pop(&block_to_free)) {
      DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), block_to_free);
      FreeBlock(block_to_free);
    }
  } else {
    // Flush the quarantine of this heap.
    ShardedBlockQuarantine::ObjectVector blocks_vec;
    quarantine->Empty(&blocks_vec);
    ShardedBlockQuarantine::ObjectVector::iterator iter_block =
        blocks_vec.begin();
    for (; iter_block != blocks_vec.end(); ++iter_block) {
      // TODO(sebmarchand): Report that the block is corrupt if this call
      //     return false.
      FreeBlock(*iter_block);
    }
  }
}

bool BlockHeapManager::FreeBlock(BlockHeader* header) {
  DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), header);
  BlockInfo block_info = {};
  if (!BlockInfoFromMemory(header, &block_info))
    return false;

  BlockHeapInterface* heap = reinterpret_cast<BlockHeapInterface*>(
      block_info.trailer->heap_id);

  if (heap == NULL)
    return false;

  // Return pointers to the stacks for reference counting purposes.
  if (block_info.header->alloc_stack != NULL) {
    stack_cache_.ReleaseStackTrace(block_info.header->alloc_stack);
    block_info.header->alloc_stack = NULL;
  }
  if (block_info.header->free_stack != NULL) {
    stack_cache_.ReleaseStackTrace(block_info.header->free_stack);
    block_info.header->free_stack = NULL;
  }

  block_info.header->state = FREED_BLOCK;

  Shadow::Unpoison(header, block_info.block_size);
  return heap->FreeBlock(block_info);
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
