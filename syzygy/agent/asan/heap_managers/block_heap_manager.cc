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

#include <utility>

#include "base/bind.h"
#include "base/rand_util.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/heaps/simple_block_heap.h"
#include "syzygy/agent/asan/heaps/win_heap.h"
#include "syzygy/common/asan_parameters.h"

namespace agent {
namespace asan {
namespace heap_managers {

namespace {

typedef HeapManagerInterface::HeapId HeapId;
using heaps::ZebraBlockHeap;

}  // namespace

BlockHeapManager::BlockHeapManager(AsanRuntime* runtime)
    : runtime_(runtime),
      zebra_block_heap_(NULL) {
  DCHECK_NE(static_cast<AsanRuntime*>(NULL), runtime);
  SetDefaultAsanParameters(&parameters_);
  // TODO(sebmarchand): Set this callback directly from AsanRuntime::Setup once
  //     everything has been plugged together.
  SetHeapErrorCallback(base::Bind(&AsanRuntime::OnError,
                                  base::Unretained(runtime_)));
  PropagateParameters();
  unguarded_allocation_heap_.reset(new heaps::WinHeap());
}

BlockHeapManager::~BlockHeapManager() {
  base::AutoLock lock(lock_);
  // Delete all the heaps.
  HeapQuarantineMap::iterator iter_heaps = heaps_.begin();
  for (; iter_heaps != heaps_.end(); ++iter_heaps)
    DestroyHeapUnlocked(iter_heaps->first, iter_heaps->second);
  heaps_.clear();
  // Clear the zebra heap reference since it was deleted.
  zebra_block_heap_ = NULL;
}

HeapId BlockHeapManager::CreateHeap() {
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

  // Some allocations can pass through without instrumentation.
  if (parameters_.allocation_guard_rate < 1.0 &&
      base::RandDouble() >= parameters_.allocation_guard_rate) {
    void* alloc = unguarded_allocation_heap_->Allocate(bytes);
    return alloc;
  }

  void* alloc = NULL;
  BlockLayout block_layout = {};

  // Always try to allocate in the zebra heap.
  if (parameters_.enable_zebra_block_heap) {
    CHECK_NE(reinterpret_cast<heaps::ZebraBlockHeap*>(NULL),
             zebra_block_heap_);

    alloc = zebra_block_heap_->AllocateBlock(
        bytes,
        0,
        parameters_.trailer_padding_size + sizeof(BlockTrailer),
        &block_layout);

    if (alloc != NULL)
      heap_id = reinterpret_cast<HeapId>(zebra_block_heap_);
  }

  // Fallback to the provided heap.
  if (alloc == NULL) {
    alloc = reinterpret_cast<BlockHeapInterface*>(heap_id)->AllocateBlock(
        bytes,
        0,
        parameters_.trailer_padding_size + sizeof(BlockTrailer),
        &block_layout);
  }

  DCHECK_NE(reinterpret_cast<void*>(NULL), alloc);
  DCHECK_EQ(0u, reinterpret_cast<size_t>(alloc) % kShadowRatio);
  BlockInfo block = {};
  BlockInitialize(block_layout, alloc, false, &block);

  // Capture the current stack. InitFromStack is inlined to preserve the
  // greatest number of stack frames.
  StackCapture stack;
  stack.InitFromStack();
  block.header->alloc_stack = runtime_->stack_cache()->SaveStackTrace(stack);
  block.header->free_stack = NULL;

  block.trailer->heap_id = heap_id;

  BlockSetChecksum(block);
  Shadow::PoisonAllocatedBlock(block);
  return block.body;
}

bool BlockHeapManager::Free(HeapId heap_id, void* alloc) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);

  BlockInfo block_info = {};
  BlockHeader* header = BlockGetHeaderFromBody(alloc);
  if (header == NULL || !Shadow::BlockInfoFromShadow(header, &block_info)) {
    // TODO(chrisha|sebmarchand): Handle invalid allocation addresses. Currently
    //     we can't tell these apart from unguarded allocations.

    // Assume that this block was allocated without guards.
    return unguarded_allocation_heap_->Free(alloc);
  }

  if (!BlockChecksumIsValid(block_info)) {
    // The free stack hasn't yet been set, but may have been filled with junk.
    // Reset it.
    block_info.header->free_stack = NULL;
    ReportHeapError(alloc, CORRUPT_BLOCK);
    return FreeCorruptBlock(&block_info);
  }

  if (block_info.header->state == QUARANTINED_BLOCK) {
    ReportHeapError(alloc, DOUBLE_FREE);
    return false;
  }

  // heap_id is just a hint, the block trailer contains the heap used for the
  // allocation.
  heap_id = block_info.trailer->heap_id;
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);

  BlockQuarantineInterface* quarantine = NULL;
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

  if (quarantine->Push(block_info.header)) {
    StackCapture stack;
    stack.InitFromStack();
    block_info.header->free_stack =
        runtime_->stack_cache()->SaveStackTrace(stack);
    block_info.trailer->free_ticks = ::GetTickCount();
    block_info.trailer->free_tid = ::GetCurrentThreadId();

    block_info.header->state = QUARANTINED_BLOCK;

    // Poison the released alloc (marked as freed) and quarantine the block.
    // Note that the original data is left intact. This may make it easier
    // to debug a crash report/dump on access to a quarantined block.
    Shadow::MarkAsFreed(block_info.body, block_info.body_size);
    BlockSetChecksum(block_info);
    TrimQuarantine(quarantine);
  } else {
    return FreePristineBlock(&block_info);
  }

  return true;
}

size_t BlockHeapManager::Size(HeapId heap_id, const void* alloc) {
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

  if (parameters_.enable_zebra_block_heap && zebra_block_heap_ == NULL) {
    // Initialize the zebra heap only if it isnt't already initialized.
    // The zebra heap cannot be resized once created.
    base::AutoLock lock(lock_);
    zebra_block_heap_ = new ZebraBlockHeap(parameters_.zebra_block_heap_size,
                                            &null_memory_notifier);
    heaps_.insert(std::make_pair(zebra_block_heap_, zebra_block_heap_));
  }

  if (zebra_block_heap_ != NULL) {
    zebra_block_heap_->set_quarantine_ratio(
      parameters_.zebra_block_heap_quarantine_ratio);
    TrimQuarantine(zebra_block_heap_);
  }

  // TODO(chrisha|sebmarchand): Clean up existing blocks that exceed the
  //     maximum block size? This will require an entirely new TrimQuarantine
  //     function. Since this is never changed at runtime except in our
  //     unittests, this is not clearly useful.
}

bool BlockHeapManager::DestroyHeapUnlocked(
    BlockHeapInterface* heap,
    BlockQuarantineInterface* quarantine) {
  DCHECK_NE(reinterpret_cast<BlockHeapInterface*>(NULL), heap);
  DCHECK_NE(reinterpret_cast<BlockQuarantineInterface*>(NULL), quarantine);

  // Starts by removing all the block from this heap from the quarantine.

  BlockQuarantineInterface::ObjectVector blocks_vec;

  // We'll keep the blocks that don't belong to this heap in a temporary list.
  // While this isn't optimal in terms of performance, destroying a heap isn't a
  // common operation.
  // TODO(sebmarchand): Add a version of the ShardedBlockQuarantine::Empty
  //     method that accepts a functor to filter the blocks to remove.
  BlockQuarantineInterface::ObjectVector blocks_to_reinsert;
  quarantine->Empty(&blocks_vec);
  BlockQuarantineInterface::ObjectVector::iterator iter_block =
      blocks_vec.begin();

  for (; iter_block != blocks_vec.end(); ++iter_block) {
    BlockInfo block_info = {};
    // If we can't retrieve the block information from the shadow then it means
    // that something went terribly wrong and that the shadow has been
    // corrupted, there's nothing we can do in this case.
    CHECK(Shadow::BlockInfoFromShadow(*iter_block, &block_info));
    if (reinterpret_cast<BlockHeapInterface*>(block_info.trailer->heap_id) ==
        heap) {
      if (!FreePotentiallyCorruptBlock(&block_info))
        return false;
    } else {
      blocks_to_reinsert.push_back(*iter_block);
    }
  }
  // Restore the blocks that don't belong to this quarantine.
  iter_block = blocks_to_reinsert.begin();
  for (; iter_block != blocks_to_reinsert.end(); ++iter_block)
    quarantine->Push(*iter_block);

  UnderlyingHeapMap::iterator iter = underlying_heaps_map_.find(heap);

  // Not all the heaps have an underlying heap.
  if (iter != underlying_heaps_map_.end()) {
    DCHECK_NE(reinterpret_cast<HeapInterface*>(NULL), iter->second);
    delete iter->second;
    underlying_heaps_map_.erase(iter);
  }

  delete heap;

  return true;
}

void BlockHeapManager::TrimQuarantine(BlockQuarantineInterface* quarantine) {
  DCHECK_NE(reinterpret_cast<BlockQuarantineInterface*>(NULL), quarantine);

  BlockQuarantineInterface::ObjectVector blocks_to_free;

  // Trim the quarantine to the new maximum size.
  if (parameters_.quarantine_size == 0) {
    quarantine->Empty(&blocks_to_free);
  } else {
    BlockHeader* block_to_free = NULL;
    while (quarantine->Pop(&block_to_free))
      blocks_to_free.push_back(block_to_free);
  }

  BlockQuarantineInterface::ObjectVector::iterator iter_block =
      blocks_to_free.begin();
  for (; iter_block != blocks_to_free.end(); ++iter_block) {
    DCHECK_NE(reinterpret_cast<BlockHeader*>(NULL), *iter_block);
    BlockInfo block_info = {};
    CHECK(Shadow::BlockInfoFromShadow(*iter_block, &block_info));
    CHECK(FreePotentiallyCorruptBlock(&block_info));
  }
}

bool BlockHeapManager::FreePotentiallyCorruptBlock(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  if (block_info->header->magic != kBlockHeaderMagic ||
      !BlockChecksumIsValid(*block_info)) {
    ReportHeapError(block_info->block, CORRUPT_BLOCK);
    return FreeCorruptBlock(block_info);
  } else {
    return FreePristineBlock(block_info);
  }
}

bool BlockHeapManager::FreeCorruptBlock(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  ClearCorruptBlockMetadata(block_info);
  return FreePristineBlock(block_info);
}

bool BlockHeapManager::FreePristineBlock(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);

  BlockHeapInterface* heap = reinterpret_cast<BlockHeapInterface*>(
      block_info->trailer->heap_id);

  if (heap == NULL) {
    // TODO(sebmarchand): Iterates over the heaps to find the one owning this
    //     block. This is currently useless as we're using the WinHeap which
    //     doesn't have the kHeapSupportsIsAllocated feature.
    return false;
  }

  // Return pointers to the stacks for reference counting purposes.
  if (block_info->header->alloc_stack != NULL) {
    runtime_->stack_cache()->ReleaseStackTrace(block_info->header->alloc_stack);
    block_info->header->alloc_stack = NULL;
  }
  if (block_info->header->free_stack != NULL) {
    runtime_->stack_cache()->ReleaseStackTrace(block_info->header->free_stack);
    block_info->header->free_stack = NULL;
  }

  block_info->header->state = FREED_BLOCK;

  Shadow::Unpoison(block_info->header, block_info->block_size);
  return heap->FreeBlock(*block_info);
}

void BlockHeapManager::ClearCorruptBlockMetadata(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  DCHECK_NE(static_cast<BlockHeader*>(NULL), block_info->header);

  // Set the invalid stack captures to NULL.
  if (!runtime_->stack_cache()->StackCapturePointerIsValid(
      block_info->header->alloc_stack)) {
    block_info->header->alloc_stack = NULL;
  }
  if (!runtime_->stack_cache()->StackCapturePointerIsValid(
      block_info->header->free_stack)) {
    block_info->header->free_stack = NULL;
  }
}

void BlockHeapManager::ReportHeapError(void* address, BadAccessKind kind) {
  DCHECK_NE(reinterpret_cast<void*>(NULL), address);

  // Collect information about the error.
  AsanErrorInfo error_info = {};
  ::RtlCaptureContext(&error_info.context);
  error_info.access_mode = agent::asan::ASAN_UNKNOWN_ACCESS;
  error_info.location = address;
  error_info.error_type = kind;
  ErrorInfoGetBadAccessInformation(runtime_->stack_cache(), &error_info);
  agent::asan::StackCapture stack;
  stack.InitFromStack();
  error_info.crash_stack_id = stack.ComputeRelativeStackId();

  // We expect a callback to be set.
  DCHECK(!heap_error_callback_.is_null());
  heap_error_callback_.Run(&error_info);
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
