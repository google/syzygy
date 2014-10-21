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
#include "syzygy/agent/asan/timed_try.h"
#include "syzygy/agent/asan/heaps/ctmalloc_heap.h"
#include "syzygy/agent/asan/heaps/internal_heap.h"
#include "syzygy/agent/asan/heaps/large_block_heap.h"
#include "syzygy/agent/asan/heaps/simple_block_heap.h"
#include "syzygy/agent/asan/heaps/win_heap.h"
#include "syzygy/agent/asan/heaps/zebra_block_heap.h"
#include "syzygy/common/asan_parameters.h"

namespace agent {
namespace asan {
namespace heap_managers {

namespace {

typedef HeapManagerInterface::HeapId HeapId;
using heaps::LargeBlockHeap;
using heaps::ZebraBlockHeap;

}  // namespace

BlockHeapManager::BlockHeapManager(StackCaptureCache* stack_cache)
    : stack_cache_(stack_cache),
      zebra_block_heap_(NULL),
      large_block_heap_(NULL) {
  DCHECK_NE(static_cast<StackCaptureCache*>(NULL), stack_cache);
  SetDefaultAsanParameters(&parameters_);
  PropagateParameters();

  // Creates the process heap and the internal heap.
  process_heap_ = NULL;
  process_heap_underlying_heap_ = NULL;
  InitProcessHeap();

  // Initialize the allocation-filter flag (using Thread Local Storage).
  allocation_filter_flag_tls_ = ::TlsAlloc();
  CHECK_NE(TLS_OUT_OF_INDEXES, allocation_filter_flag_tls_);
  // And disable it by default.
  set_allocation_filter_flag(false);
}

BlockHeapManager::~BlockHeapManager() {
  base::AutoLock lock(lock_);
  // Delete all the heaps.
  HeapQuarantineMap::iterator iter_heaps = heaps_.begin();
  for (; iter_heaps != heaps_.end(); ++iter_heaps)
    DestroyHeapUnlocked(iter_heaps->first, iter_heaps->second);
  heaps_.clear();

  process_heap_ = NULL;
  // Clear the specialized heap references since they were deleted.
  zebra_block_heap_ = NULL;
  large_block_heap_ = NULL;

  // Free the allocation-filter flag (TLS).
  CHECK_NE(TLS_OUT_OF_INDEXES, allocation_filter_flag_tls_);
  ::TlsFree(allocation_filter_flag_tls_);
  // Invalidate the TLS slot.
  allocation_filter_flag_tls_ = TLS_OUT_OF_INDEXES;
}

HeapId BlockHeapManager::CreateHeap() {
  // Creates the underlying heap used by this heap.
  HeapInterface* underlying_heap = NULL;
  if (parameters_.enable_ctmalloc) {
    underlying_heap = new heaps::CtMallocHeap(&shadow_memory_notifier_);
  } else {
    underlying_heap = new heaps::WinHeap();
  }
  // Creates the heap.
  BlockHeapInterface* heap = new heaps::SimpleBlockHeap(underlying_heap);

  base::AutoLock lock(lock_);
  underlying_heaps_map_.insert(std::make_pair(heap, underlying_heap));
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
    HeapInterface* heap = reinterpret_cast<HeapInterface*>(heap_id);
    void* alloc = heap->Allocate(bytes);
    if ((heap->GetHeapFeatures() &
       HeapInterface::kHeapReportsReservations) != 0) {
      Shadow::Unpoison(alloc, bytes);
    }
    return alloc;
  }

  // Build the set of heaps that will be used to satisfy the allocation. This
  // is a stack of heaps, and they will be tried in the reverse order they are
  // inserted.

  // We can always use the heap that was passed in.
  BlockHeapInterface* heaps[3] = {
      reinterpret_cast<BlockHeapInterface*>(heap_id), 0, 0 };
  size_t heap_count = 1;
  if (MayUseLargeBlockHeap(bytes)) {
    DCHECK_NE(reinterpret_cast<LargeBlockHeap*>(NULL), large_block_heap_);
    DCHECK_LT(heap_count, arraysize(heaps));
    heaps[heap_count++] = large_block_heap_;
  }

  if (MayUseZebraBlockHeap(bytes)) {
    DCHECK_NE(reinterpret_cast<ZebraBlockHeap*>(NULL), zebra_block_heap_);
    DCHECK_LT(heap_count, arraysize(heaps));
    heaps[heap_count++] = zebra_block_heap_;
  }

  // Use the selected heaps to try to satisfy the allocation.
  void* alloc = NULL;
  BlockLayout block_layout = {};
  for (int i = static_cast<int>(heap_count) - 1; i >= 0; --i) {
    alloc = heaps[i]->AllocateBlock(
        bytes,
        0,
        parameters_.trailer_padding_size + sizeof(BlockTrailer),
        &block_layout);
    if (alloc != NULL) {
      heap_id = reinterpret_cast<HeapId>(heaps[i]);
      break;
    }
  }

  // The allocation can fail if we're out of memory.
  if (alloc == NULL)
    return NULL;

  DCHECK_NE(reinterpret_cast<void*>(NULL), alloc);
  DCHECK_EQ(0u, reinterpret_cast<size_t>(alloc) % kShadowRatio);
  BlockInfo block = {};
  BlockInitialize(block_layout, alloc, false, &block);

  // Capture the current stack. InitFromStack is inlined to preserve the
  // greatest number of stack frames.
  StackCapture stack;
  stack.InitFromStack();
  block.header->alloc_stack = stack_cache_->SaveStackTrace(stack);
  block.header->free_stack = NULL;
  block.header->state = ALLOCATED_BLOCK;

  block.trailer->heap_id = heap_id;

  BlockSetChecksum(block);
  Shadow::PoisonAllocatedBlock(block);
  BlockProtectRedzones(block);

  return block.body;
}

bool BlockHeapManager::Free(HeapId heap_id, void* alloc) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);

  // The standard allows calling free on a null pointer.
  if (alloc == NULL)
    return true;

  BlockInfo block_info = {};
  if (!Shadow::IsBeginningOfBlockBody(alloc) ||
      !Shadow::BlockInfoFromShadow(alloc, &block_info)) {
    return FreeUnguardedAlloc(reinterpret_cast<HeapInterface*>(heap_id), alloc);
  }

  // Precondition: A valid guarded allocation.
  BlockProtectNone(block_info);

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

  // We need to update the block's metadata before pushing it into the
  // quarantine, otherwise a concurrent thread might try to pop it while its in
  // an invalid state.
  StackCapture stack;
  stack.InitFromStack();
  block_info.header->free_stack =
      stack_cache_->SaveStackTrace(stack);
  block_info.trailer->free_ticks = ::GetTickCount();
  block_info.trailer->free_tid = ::GetCurrentThreadId();

  block_info.header->state = QUARANTINED_BLOCK;

  // Poison the released alloc (marked as freed) and quarantine the block.
  // Note that the original data is left intact. This may make it easier
  // to debug a crash report/dump on access to a quarantined block.
  Shadow::MarkAsFreed(block_info.body, block_info.body_size);
  BlockSetChecksum(block_info);

  {
    BlockQuarantineInterface::AutoQuarantineLock quarantine_lock(
        quarantine, block_info.header);
    if (!quarantine->Push(block_info.header))
      return FreePristineBlock(&block_info);

    // The recently pushed block can be popped out in TrimQuarantine if the
    // quarantine size is 0, in that case TrimQuarantine takes care of properly
    // unprotecting and freeing the block. If the protection is set blindly
    // after TrimQuarantine we could end up protecting a free (not quarantined,
    // not allocated) block.
    BlockProtectAll(block_info);
  }
  TrimQuarantine(quarantine);
  return true;
}

size_t BlockHeapManager::Size(HeapId heap_id, const void* alloc) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);
  if (Shadow::IsBeginningOfBlockBody(alloc)) {
    BlockInfo block_info = {};
    if (!Shadow::BlockInfoFromShadow(alloc, &block_info))
      return 0;
    return block_info.body_size;
  }
  HeapInterface* heap = reinterpret_cast<HeapInterface*>(heap_id);
  if ((heap->GetHeapFeatures() &
        HeapInterface::kHeapSupportsGetAllocationSize) != 0) {
    return heap->GetAllocationSize(alloc);
  } else {
    return 0;
  }
}

void BlockHeapManager::Lock(HeapId heap_id) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);
  reinterpret_cast<HeapInterface*>(heap_id)->Lock();
}

void BlockHeapManager::Unlock(HeapId heap_id) {
  DCHECK_NE(static_cast<HeapId>(NULL), heap_id);
  reinterpret_cast<HeapInterface*>(heap_id)->Unlock();
}

void BlockHeapManager::BestEffortLockAll() {
  static const base::TimeDelta kTryTime(base::TimeDelta::FromMilliseconds(50));
  lock_.Acquire();
  DCHECK(locked_heaps_.empty());
  for (auto& heap_quarantine_pair : heaps_) {
    HeapInterface* heap = heap_quarantine_pair.first;
    if (TimedTry(kTryTime, heap))
      locked_heaps_.insert(heap);
  }
}

void BlockHeapManager::UnlockAll() {
  lock_.AssertAcquired();
  for (HeapInterface* heap : locked_heaps_)
    heap->Unlock();
  locked_heaps_.clear();
  lock_.Release();
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
    // Initialize the zebra heap only if it isn't already initialized.
    // The zebra heap cannot be resized once created.
    base::AutoLock lock(lock_);
    zebra_block_heap_ = new ZebraBlockHeap(parameters_.zebra_block_heap_size,
                                           &shadow_memory_notifier_,
                                           internal_heap_.get());
    heaps_.insert(std::make_pair(zebra_block_heap_, zebra_block_heap_));
  }

  if (zebra_block_heap_ != NULL) {
    zebra_block_heap_->set_quarantine_ratio(
        parameters_.zebra_block_heap_quarantine_ratio);
    TrimQuarantine(zebra_block_heap_);
  }

  // Create the LargeBlockHeap if need be.
  if (parameters_.enable_large_block_heap && large_block_heap_ == NULL) {
    base::AutoLock lock(lock_);
    large_block_heap_ = new LargeBlockHeap(internal_heap_.get());
    heaps_.insert(std::make_pair(large_block_heap_, &shared_quarantine_));
  }

  // TODO(chrisha|sebmarchand): Clean up existing blocks that exceed the
  //     maximum block size? This will require an entirely new TrimQuarantine
  //     function. Since this is never changed at runtime except in our
  //     unittests, this is not clearly useful.
}

bool BlockHeapManager::allocation_filter_flag() const {
  return reinterpret_cast<bool>(::TlsGetValue(allocation_filter_flag_tls_));
}

void BlockHeapManager::set_allocation_filter_flag(bool value) {
  ::TlsSetValue(allocation_filter_flag_tls_, reinterpret_cast<void*>(value));
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

    // Remove protection to be able to access to the block header.
    BlockProtectNone(block_info);
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
  for (; iter_block != blocks_to_reinsert.end(); ++iter_block) {
    BlockInfo block_info = {};
    CHECK(Shadow::BlockInfoFromShadow(*iter_block, &block_info));
    BlockQuarantineInterface::AutoQuarantineLock quarantine_lock(quarantine,
                                                                 *iter_block);
    if (quarantine->Push(*iter_block)) {
      // Restore protection to quarantined block.
      BlockProtectAll(block_info);
    } else {
      // Avoid memory leak.
      CHECK(FreePotentiallyCorruptBlock(&block_info));
    }
  }

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

  BlockProtectNone(*block_info);

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

  BlockProtectNone(*block_info);

  // Return pointers to the stacks for reference counting purposes.
  if (block_info->header->alloc_stack != NULL) {
    stack_cache_->ReleaseStackTrace(block_info->header->alloc_stack);
    block_info->header->alloc_stack = NULL;
  }
  if (block_info->header->free_stack != NULL) {
    stack_cache_->ReleaseStackTrace(block_info->header->free_stack);
    block_info->header->free_stack = NULL;
  }

  block_info->header->state = FREED_BLOCK;

  if ((heap->GetHeapFeatures() &
       HeapInterface::kHeapReportsReservations) != 0) {
    Shadow::Poison(block_info->block, block_info->block_size,
                   kAsanReservedMarker);
  } else {
    Shadow::Unpoison(block_info->block, block_info->block_size);
  }
  return heap->FreeBlock(*block_info);
}

bool BlockHeapManager::FreeUnguardedAlloc(HeapInterface* heap, void* alloc) {
  DCHECK_NE(static_cast<HeapInterface*>(NULL), heap);

  // Check if the allocation comes from the process heap, if so there's two
  // possibilities:
  //   - CTMalloc is enabled, in this case the process heap underlying heap is
  //     a CTMalloc heap. In this case the allocation might still have been
  //     allocated against the real process heap, free it in this case.
  //   - CTMalloc is disabled and in this case the process heap underlying heap
  //     is always the real process heap.
  if (heap == process_heap_ &&
      (!parameters_.enable_ctmalloc || !heap->IsAllocated(alloc))) {
    return ::HeapFree(::GetProcessHeap(), 0, alloc) == TRUE;
  }
  if ((heap->GetHeapFeatures() &
       HeapInterface::kHeapReportsReservations) != 0) {
    DCHECK_NE(0U, heap->GetHeapFeatures() &
                  HeapInterface::kHeapSupportsGetAllocationSize);
    Shadow::Poison(alloc,
                   Size(reinterpret_cast<HeapId>(heap), alloc),
                   kAsanReservedMarker);
  }
  return heap->Free(alloc);
}

void BlockHeapManager::ClearCorruptBlockMetadata(BlockInfo* block_info) {
  DCHECK_NE(static_cast<BlockInfo*>(NULL), block_info);
  DCHECK_NE(static_cast<BlockHeader*>(NULL), block_info->header);

  // Set the invalid stack captures to NULL.
  if (!stack_cache_->StackCapturePointerIsValid(
      block_info->header->alloc_stack)) {
    block_info->header->alloc_stack = NULL;
  }
  if (!stack_cache_->StackCapturePointerIsValid(
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
  ErrorInfoGetBadAccessInformation(stack_cache_, &error_info);
  agent::asan::StackCapture stack;
  stack.InitFromStack();
  error_info.crash_stack_id = stack.ComputeRelativeStackId();

  // We expect a callback to be set.
  DCHECK(!heap_error_callback_.is_null());
  heap_error_callback_.Run(&error_info);
}

void BlockHeapManager::InitProcessHeap() {
  CHECK_EQ(reinterpret_cast<BlockHeapInterface*>(NULL), process_heap_);
  if (parameters_.enable_ctmalloc) {
    internal_heap_.reset(
        new heaps::CtMallocHeap(&shadow_memory_notifier_));
    process_heap_underlying_heap_ =
        new heaps::CtMallocHeap(&shadow_memory_notifier_);
  } else {
    internal_win_heap_.reset(new heaps::WinHeap);
    internal_heap_.reset(new heaps::InternalHeap(&shadow_memory_notifier_,
                                                 internal_win_heap_.get()));
    process_heap_underlying_heap_ = new heaps::WinHeap(::GetProcessHeap());
  }
  process_heap_ = new heaps::SimpleBlockHeap(process_heap_underlying_heap_);
  underlying_heaps_map_.insert(std::make_pair(process_heap_,
                                              process_heap_underlying_heap_));
  heaps_.insert(std::make_pair(process_heap_, &shared_quarantine_));
}

bool BlockHeapManager::MayUseLargeBlockHeap(size_t bytes) const {
  if (!parameters_.enable_large_block_heap)
    return false;
  if (bytes >= parameters_.large_allocation_threshold)
    return true;

  // If we get here we're treating a small allocation. If the allocation
  // filter is in effect and the flag set then allow it.
  if (parameters_.enable_allocation_filter && allocation_filter_flag())
    return true;

  return false;
}

bool BlockHeapManager::MayUseZebraBlockHeap(size_t bytes) const {
  if (!parameters_.enable_zebra_block_heap)
    return false;
  if (bytes > ZebraBlockHeap::kMaximumBlockAllocationSize)
    return false;

  // If the allocation filter is in effect only allow filtered allocations
  // into the zebra heap.
  if (parameters_.enable_allocation_filter)
    return allocation_filter_flag();

  // Otherwise, allow everything through.
  return true;
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
