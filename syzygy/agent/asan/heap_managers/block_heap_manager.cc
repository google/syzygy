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

#include <algorithm>
#include <utility>

#include "base/bind.h"
#include "base/rand_util.h"
#include "syzygy/agent/asan/page_protection_helpers.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/agent/asan/shadow.h"
#include "syzygy/agent/asan/timed_try.h"
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

// For now, the overbudget size is always set to 20% of the size of the
// quarantine.
// TODO(georgesak): allow this to be changed through the parameters.
enum : uint32_t { kOverbudgetSizePercentage = 20 };

// Return the position of the most significant bit in a 32 bit unsigned value.
size_t GetMSBIndex(size_t n) {
  // Algorithm taken from
  // http://graphics.stanford.edu/~seander/bithacks.html#IntegerLog
  size_t r = 0;
  size_t shift = 0;
  r = (n > 0xFFFF) << 4;
  n >>= r;
  shift = (n > 0xFF) << 3;
  n >>= shift;
  r |= shift;
  shift = (n > 0xF) << 2;
  n >>= shift;
  r |= shift;
  shift = (n > 0x3) << 1;
  n >>= shift;
  r |= shift;
  r |= (n >> 1);
  return r;
}

// Try to do an unguarded allocation.
// @param heap_interface The heap that should serve the allocation.
// @param shadow The shadow memory.
// @param bytes The size of the allocation.
// @returns a pointer to the allocation on success, nullptr otherwise.
void* DoUnguardedAllocation(BlockHeapInterface* heap_interface,
                            Shadow* shadow,
                            uint32_t bytes) {
  void* alloc = heap_interface->Allocate(bytes);
  if ((heap_interface->GetHeapFeatures() &
       HeapInterface::kHeapReportsReservations) != 0) {
    shadow->Unpoison(alloc, bytes);
  }
  return alloc;
}

}  // namespace

BlockHeapManager::BlockHeapManager(Shadow* shadow,
                                   StackCaptureCache* stack_cache,
                                   MemoryNotifierInterface* memory_notifier)
    : shadow_(shadow),
      stack_cache_(stack_cache),
      memory_notifier_(memory_notifier),
      initialized_(false),
      process_heap_(nullptr),
      process_heap_underlying_heap_(nullptr),
      process_heap_id_(0),
      zebra_block_heap_(nullptr),
      zebra_block_heap_id_(0),
      large_block_heap_id_(0),
      locked_heaps_(nullptr),
      enable_page_protections_(true) {
  DCHECK_NE(static_cast<Shadow*>(nullptr), shadow);
  DCHECK_NE(static_cast<StackCaptureCache*>(nullptr), stack_cache);
  DCHECK_NE(static_cast<MemoryNotifierInterface*>(nullptr), memory_notifier);
  SetDefaultAsanParameters(&parameters_);

  // Initialize the allocation-filter flag (using Thread Local Storage).
  allocation_filter_flag_tls_ = ::TlsAlloc();
  CHECK_NE(TLS_OUT_OF_INDEXES, allocation_filter_flag_tls_);
  // And disable it by default.
  set_allocation_filter_flag(false);
}

BlockHeapManager::~BlockHeapManager() {
  TearDownHeapManager();
}

void BlockHeapManager::Init() {
  DCHECK(!initialized_);

  {
    base::AutoLock lock(lock_);
    InitInternalHeap();

    // Only create a registry cache if the registry is available. It is not
    // available in sandboxed Chrome renderer processes.
    if (RegistryCache::RegistryAvailable()) {
      corrupt_block_registry_cache_.reset(
          new RegistryCache(L"SyzyAsanCorruptBlocks"));
      corrupt_block_registry_cache_->Init();
    }
  }

  // This takes care of its own locking, as its reentrant.
  PropagateParameters();

  {
    base::AutoLock lock(lock_);
    InitProcessHeap();
    initialized_ = true;
  }
}

HeapId BlockHeapManager::CreateHeap() {
  DCHECK(initialized_);

  // Creates the underlying heap used by this heap.
  // TODO(chrisha): We should be using the internal allocator for these
  //     heap allocations!
  HeapInterface* underlying_heap = new heaps::WinHeap();
  // Creates the heap.
  BlockHeapInterface* heap = new heaps::SimpleBlockHeap(underlying_heap);

  base::AutoLock lock(lock_);
  underlying_heaps_map_.insert(std::make_pair(heap, underlying_heap));
  HeapMetadata metadata = { &shared_quarantine_, false };
  auto result = heaps_.insert(std::make_pair(heap, metadata));
  return GetHeapId(result);
}

bool BlockHeapManager::DestroyHeap(HeapId heap_id) {
  DCHECK(initialized_);
  DCHECK(IsValidHeapId(heap_id, false));
  BlockHeapInterface* heap = GetHeapFromId(heap_id);
  BlockQuarantineInterface* quarantine = GetQuarantineFromId(heap_id);

  {
    // Move the heap from the active to the dying list. This prevents it from
    // being used while it's being torn down.
    base::AutoLock lock(lock_);
    auto iter = heaps_.find(heap);
    iter->second.is_dying = true;
  }

  // Destroy the heap and flush its quarantine. This is done outside of the
  // lock to both reduce contention and to ensure that we can re-enter the
  // block heap manager if corruption is found during the heap tear down.
  DestroyHeapContents(heap, quarantine);

  // Free up any resources associated with the heap. This modifies block
  // heap manager internals, so must be called under a lock.
  {
    base::AutoLock lock(lock_);
    DestroyHeapResourcesUnlocked(heap, quarantine);
    heaps_.erase(heaps_.find(heap));
  }

  return true;
}

void* BlockHeapManager::Allocate(HeapId heap_id, uint32_t bytes) {
  DCHECK(initialized_);
  DCHECK(IsValidHeapId(heap_id, false));

  // Some allocations can pass through without instrumentation.
  if (parameters_.allocation_guard_rate < 1.0 &&
      base::RandDouble() >= parameters_.allocation_guard_rate) {
    return DoUnguardedAllocation(GetHeapFromId(heap_id), shadow_, bytes);
  }

  // Capture the current stack. InitFromStack is inlined to preserve the
  // greatest number of stack frames.
  common::StackCapture stack;
  stack.InitFromStack();

  // Build the set of heaps that will be used to satisfy the allocation. This
  // is a stack of heaps, and they will be tried in the reverse order they are
  // inserted.

  // We can always use the heap that was passed in.
  HeapId heaps[3] = { heap_id, 0, 0 };
  size_t heap_count = 1;
  if (MayUseLargeBlockHeap(bytes)) {
    DCHECK_LT(heap_count, arraysize(heaps));
    heaps[heap_count++] = large_block_heap_id_;
  }

  if (MayUseZebraBlockHeap(bytes)) {
    DCHECK_LT(heap_count, arraysize(heaps));
    heaps[heap_count++] = zebra_block_heap_id_;
  }

  // Use the selected heaps to try to satisfy the allocation.
  void* alloc = nullptr;
  BlockLayout block_layout = {};
  for (int i = static_cast<int>(heap_count) - 1; i >= 0; --i) {
    BlockHeapInterface* heap = GetHeapFromId(heaps[i]);
    alloc = heap->AllocateBlock(
        bytes,
        0,
        parameters_.trailer_padding_size + sizeof(BlockTrailer),
        &block_layout);
    if (alloc != nullptr) {
      heap_id = heaps[i];
      break;
    }
  }

  // The allocation can fail if we're out of memory or if the size exceed the
  // maximum allocation size.
  if (alloc == nullptr)
    return nullptr;

  DCHECK_NE(static_cast<void*>(nullptr), alloc);
  DCHECK_EQ(0u, reinterpret_cast<size_t>(alloc) % kShadowRatio);
  BlockInfo block = {};
  BlockInitialize(block_layout, alloc, &block);

  // Poison the redzones in the shadow memory as early as possible.
  shadow_->PoisonAllocatedBlock(block);

  block.header->alloc_stack = stack_cache_->SaveStackTrace(stack);
  block.header->free_stack = nullptr;
  block.header->state = ALLOCATED_BLOCK;

  block.trailer->heap_id = heap_id;

  BlockSetChecksum(block);
  if (enable_page_protections_)
    BlockProtectRedzones(block, shadow_);

  return block.body;
}

bool BlockHeapManager::Free(HeapId heap_id, void* alloc) {
  DCHECK(initialized_);
  DCHECK(IsValidHeapId(heap_id, false));

  // The standard allows calling free on a null pointer.
  if (alloc == nullptr)
    return true;

  BlockInfo block_info = {};
  if (!shadow_->IsBeginningOfBlockBody(alloc) ||
      !GetBlockInfo(shadow_, reinterpret_cast<BlockBody*>(alloc),
                    &block_info)) {
    return FreeUnguardedAlloc(heap_id, alloc);
  }

  if (enable_page_protections_) {
    // Precondition: A valid guarded allocation.
    BlockProtectNone(block_info, shadow_);
  }

  if (!BlockChecksumIsValid(block_info)) {
    // The free stack hasn't yet been set, but may have been filled with junk.
    // Reset it.
    block_info.header->free_stack = nullptr;
    if (ShouldReportCorruptBlock(&block_info))
      ReportHeapError(alloc, CORRUPT_BLOCK);
    return FreeCorruptBlock(&block_info);
  }

  if (block_info.header->state == QUARANTINED_BLOCK ||
      block_info.header->state == QUARANTINED_FLOODED_BLOCK) {
    ReportHeapError(alloc, DOUBLE_FREE);
    return false;
  }

  // heap_id is just a hint, the block trailer contains the heap used for the
  // allocation.
  heap_id = block_info.trailer->heap_id;
  BlockQuarantineInterface* quarantine = GetQuarantineFromId(heap_id);

  // Poison the released alloc (marked as freed) and quarantine the block.
  // Note that the original data is left intact. This may make it easier
  // to debug a crash report/dump on access to a quarantined block.
  shadow_->MarkAsFreed(block_info.body, block_info.body_size);

  // We need to update the block's metadata before pushing it into the
  // quarantine, otherwise a concurrent thread might try to pop it while its in
  // an invalid state.
  common::StackCapture stack;
  stack.InitFromStack();
  block_info.header->free_stack =
      stack_cache_->SaveStackTrace(stack);
  block_info.trailer->free_ticks = ::GetTickCount();
  block_info.trailer->free_tid = ::GetCurrentThreadId();

  // Flip a coin and sometimes flood the block. When flooded, overwrites are
  // clearly visible; when not flooded, the original contents are left visible.
  bool flood = parameters_.quarantine_flood_fill_rate > 0.0 &&
      base::RandDouble() <= parameters_.quarantine_flood_fill_rate;
  if (flood) {
    block_info.header->state = QUARANTINED_FLOODED_BLOCK;
    ::memset(block_info.body, kBlockFloodFillByte, block_info.body_size);
  } else {
    block_info.header->state = QUARANTINED_BLOCK;
  }

  // Update the block checksum.
  BlockSetChecksum(block_info);

  CompactBlockInfo compact = {};
  ConvertBlockInfo(block_info, &compact);

  PushResult push_result = {};
  {
    BlockQuarantineInterface::AutoQuarantineLock quarantine_lock(
        quarantine, compact);
    push_result = quarantine->Push(compact);
    if (!push_result.push_successful) {
      TrimOrScheduleIfNecessary(push_result.trim_status, quarantine);
      return FreePristineBlock(&block_info);
    }

    if (enable_page_protections_) {
      // The recently pushed block can be popped out in TrimQuarantine if the
      // quarantine size is 0, in that case TrimQuarantine takes care of
      // properly unprotecting and freeing the block. If the protection is set
      // blindly after TrimQuarantine we could end up protecting a free (not
      // quarantined, not allocated) block.
      BlockProtectAll(block_info, shadow_);
    }
  }

  TrimOrScheduleIfNecessary(push_result.trim_status, quarantine);

  return true;
}

uint32_t BlockHeapManager::Size(HeapId heap_id, const void* alloc) {
  DCHECK(initialized_);
  DCHECK(IsValidHeapId(heap_id, false));

  if (shadow_->IsBeginningOfBlockBody(alloc)) {
    BlockInfo block_info = {};
    if (!GetBlockInfo(shadow_, reinterpret_cast<const BlockBody*>(alloc),
                      &block_info)) {
      return 0;
    }
    return block_info.body_size;
  }

  BlockHeapInterface* heap = GetHeapFromId(heap_id);
  if ((heap->GetHeapFeatures() &
        HeapInterface::kHeapSupportsGetAllocationSize) != 0) {
    return heap->GetAllocationSize(alloc);
  } else {
    return 0;
  }
}

void BlockHeapManager::Lock(HeapId heap_id) {
  DCHECK(initialized_);
  DCHECK(IsValidHeapId(heap_id, false));
  GetHeapFromId(heap_id)->Lock();
}

void BlockHeapManager::Unlock(HeapId heap_id) {
  DCHECK(initialized_);
  DCHECK(IsValidHeapId(heap_id, false));
  GetHeapFromId(heap_id)->Unlock();
}

void BlockHeapManager::BestEffortLockAll() {
  DCHECK(initialized_);
  static const base::TimeDelta kTryTime(base::TimeDelta::FromMilliseconds(50));
  lock_.Acquire();

  // Create room to store the list of locked heaps. This must use the internal
  // heap as any other heap may be involved in a crash and locked right now.
  DCHECK_EQ(static_cast<HeapInterface**>(nullptr), locked_heaps_);
  uint32_t alloc_size = sizeof(HeapInterface*) *
      static_cast<uint32_t>(heaps_.size() + 1);
  locked_heaps_ = reinterpret_cast<HeapInterface**>(internal_heap_->Allocate(
      alloc_size));
  DCHECK_NE(static_cast<HeapInterface**>(nullptr), locked_heaps_);
  ::memset(locked_heaps_, 0, alloc_size);

  size_t index = 0;
  for (auto& heap_quarantine_pair : heaps_) {
    HeapInterface* heap = heap_quarantine_pair.first;
    if (TimedTry(kTryTime, heap)) {
      locked_heaps_[index] = heap;
      ++index;
    }
  }
}

void BlockHeapManager::UnlockAll() {
  DCHECK(initialized_);
  lock_.AssertAcquired();
  DCHECK_NE(static_cast<HeapInterface**>(nullptr), locked_heaps_);
  for (HeapInterface** heap = locked_heaps_; *heap != nullptr; ++heap)
    (*heap)->Unlock();
  internal_heap_->Free(locked_heaps_);
  locked_heaps_ = nullptr;
  lock_.Release();
}

void BlockHeapManager::set_parameters(
    const ::common::AsanParameters& parameters) {
  {
    base::AutoLock lock(lock_);
    parameters_ = parameters;
  }

  // Releases the lock before propagating the parameters.
  if (initialized_)
    PropagateParameters();
}

void BlockHeapManager::TearDownHeapManager() {
  base::AutoLock lock(lock_);

  // This would indicate that we have outstanding heap locks being
  // held. This shouldn't happen as |locked_heaps_| is only non-null
  // under |lock_|.
  DCHECK_EQ(static_cast<HeapInterface**>(nullptr), locked_heaps_);

  // Delete all the heaps. This must be done manually to ensure that
  // all references to internal_heap_ have been cleaned up.
  HeapQuarantineMap::iterator iter_heaps = heaps_.begin();
  for (; iter_heaps != heaps_.end(); ++iter_heaps) {
    DCHECK(!iter_heaps->second.is_dying);
    iter_heaps->second.is_dying = true;
    DestroyHeapContents(iter_heaps->first, iter_heaps->second.quarantine);
    DestroyHeapResourcesUnlocked(iter_heaps->first,
                                 iter_heaps->second.quarantine);
  }
  // Clear the active heap list.
  heaps_.clear();

  // Clear the specialized heap references since they were deleted.
  process_heap_ = nullptr;
  process_heap_underlying_heap_ = nullptr;
  process_heap_id_ = 0;
  zebra_block_heap_ = nullptr;
  zebra_block_heap_id_ = 0;
  large_block_heap_id_ = 0;

  // Free the allocation-filter flag (TLS).
  if (allocation_filter_flag_tls_ != TLS_OUT_OF_INDEXES) {
    ::TlsFree(allocation_filter_flag_tls_);
    allocation_filter_flag_tls_ = TLS_OUT_OF_INDEXES;
  }
}

HeapId BlockHeapManager::GetHeapId(
    HeapQuarantineMap::iterator iterator) const {
  HeapQuarantinePair* hq_pair = &(*iterator);
  return reinterpret_cast<HeapId>(hq_pair);
}

HeapId BlockHeapManager::GetHeapId(
    const std::pair<HeapQuarantineMap::iterator, bool>& insert_result) const {
  return GetHeapId(insert_result.first);
}

bool BlockHeapManager::IsValidHeapIdUnsafe(HeapId heap_id, bool allow_dying) {
  DCHECK(initialized_);
  HeapQuarantinePair* hq = reinterpret_cast<HeapQuarantinePair*>(heap_id);
  if (!IsValidHeapIdUnsafeUnlockedImpl1(hq))
    return false;
  base::AutoLock auto_lock(lock_);
  if (!IsValidHeapIdUnlockedImpl2(hq, allow_dying))
    return false;
  return true;
}

bool BlockHeapManager::IsValidHeapIdUnsafeUnlocked(
    HeapId heap_id, bool allow_dying) {
  DCHECK(initialized_);
  HeapQuarantinePair* hq = reinterpret_cast<HeapQuarantinePair*>(heap_id);
  if (!IsValidHeapIdUnsafeUnlockedImpl1(hq))
    return false;
  if (!IsValidHeapIdUnlockedImpl2(hq, allow_dying))
    return false;
  return true;
}

bool BlockHeapManager::IsValidHeapId(HeapId heap_id, bool allow_dying) {
  DCHECK(initialized_);
  HeapQuarantinePair* hq = reinterpret_cast<HeapQuarantinePair*>(heap_id);
  if (!IsValidHeapIdUnlockedImpl1(hq))
    return false;
  base::AutoLock auto_lock(lock_);
  if (!IsValidHeapIdUnlockedImpl2(hq, allow_dying))
    return false;
  return true;
}

bool BlockHeapManager::IsValidHeapIdUnlocked(HeapId heap_id, bool allow_dying) {
  DCHECK(initialized_);
  HeapQuarantinePair* hq = reinterpret_cast<HeapQuarantinePair*>(heap_id);
  if (!IsValidHeapIdUnlockedImpl1(hq))
    return false;
  if (!IsValidHeapIdUnlockedImpl2(hq, allow_dying))
    return false;
  return true;
}

bool BlockHeapManager::IsValidHeapIdUnsafeUnlockedImpl1(
    HeapQuarantinePair* hq) {
  // First check to see if it looks like it has the right shape. This could
  // cause an invalid access if the heap_id is completely a wild value.
  if (hq == nullptr)
    return false;
  if (hq->first == nullptr || hq->second.quarantine == nullptr)
    return false;
  return true;
}

bool BlockHeapManager::IsValidHeapIdUnlockedImpl1(
    HeapQuarantinePair* hq) {
  // Run this in an exception handler, as if it's a really invalid heap id
  // we could end up reading from inaccessible memory.
  __try {
    if (!IsValidHeapIdUnsafeUnlockedImpl1(hq))
      return false;
  } __except(EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
  return true;
}

bool BlockHeapManager::IsValidHeapIdUnlockedImpl2(HeapQuarantinePair* hq,
                                                  bool allow_dying) {
  // Look in the list of live heaps first.
  auto it = heaps_.find(hq->first);
  if (it != heaps_.end()) {
    HeapId heap_id = GetHeapId(it);
    if (heap_id == reinterpret_cast<HeapId>(hq))
      return !it->second.is_dying || allow_dying;
  }

  return false;
}

BlockHeapInterface* BlockHeapManager::GetHeapFromId(HeapId heap_id) {
  DCHECK_NE(reinterpret_cast<HeapId>(nullptr), heap_id);
  HeapQuarantinePair* hq = reinterpret_cast<HeapQuarantinePair*>(heap_id);
  DCHECK_NE(static_cast<BlockHeapInterface*>(nullptr), hq->first);
  return hq->first;
}

BlockQuarantineInterface* BlockHeapManager::GetQuarantineFromId(
    HeapId heap_id) {
  DCHECK_NE(reinterpret_cast<HeapId>(nullptr), heap_id);
  HeapQuarantinePair* hq = reinterpret_cast<HeapQuarantinePair*>(heap_id);
  DCHECK_NE(static_cast<BlockQuarantineInterface*>(nullptr),
            hq->second.quarantine);
  return hq->second.quarantine;
}

void BlockHeapManager::PropagateParameters() {
  // The internal heap should already be setup.
  DCHECK_NE(static_cast<HeapInterface*>(nullptr), internal_heap_.get());

  size_t quarantine_size = shared_quarantine_.max_quarantine_size();
  shared_quarantine_.set_max_quarantine_size(parameters_.quarantine_size);
  shared_quarantine_.set_max_object_size(parameters_.quarantine_block_size);

  // Trim the quarantine if its maximum size has decreased.
  if (initialized_ && quarantine_size > parameters_.quarantine_size)
    TrimQuarantine(TrimColor::YELLOW, &shared_quarantine_);

  if (parameters_.enable_zebra_block_heap && zebra_block_heap_ == nullptr) {
    // Initialize the zebra heap only if it isn't already initialized.
    // The zebra heap cannot be resized once created.
    base::AutoLock lock(lock_);
    zebra_block_heap_ = new ZebraBlockHeap(parameters_.zebra_block_heap_size,
                                           memory_notifier_,
                                           internal_heap_.get());
    // The zebra block heap is its own quarantine.
    HeapMetadata heap_metadata = { zebra_block_heap_, false };
    auto result = heaps_.insert(std::make_pair(zebra_block_heap_,
                                               heap_metadata));
    zebra_block_heap_id_ = GetHeapId(result);
  }

  if (zebra_block_heap_ != nullptr) {
    zebra_block_heap_->set_quarantine_ratio(
        parameters_.zebra_block_heap_quarantine_ratio);
    if (initialized_)
      TrimQuarantine(TrimColor::YELLOW, zebra_block_heap_);
  }

  // Create the LargeBlockHeap if need be.
  if (parameters_.enable_large_block_heap && large_block_heap_id_ == 0) {
    base::AutoLock lock(lock_);
    BlockHeapInterface* heap = new LargeBlockHeap(
        memory_notifier_, internal_heap_.get());
    HeapMetadata metadata = { &shared_quarantine_, false };
    auto result = heaps_.insert(std::make_pair(heap, metadata));
    large_block_heap_id_ = GetHeapId(result);
  }

  // TODO(chrisha|sebmarchand): Clean up existing blocks that exceed the
  //     maximum block size? This will require an entirely new TrimQuarantine
  //     function. Since this is never changed at runtime except in our
  //     unittests, this is not clearly useful.
}

bool BlockHeapManager::allocation_filter_flag() const {
  return ::TlsGetValue(allocation_filter_flag_tls_) != 0;
}

void BlockHeapManager::set_allocation_filter_flag(bool value) {
  ::TlsSetValue(allocation_filter_flag_tls_, reinterpret_cast<void*>(value));
}

void BlockHeapManager::EnableDeferredFreeThread() {
  // The thread will be shutdown before this BlockHeapManager object is
  // destroyed, so passing |this| unretained is safe.
  EnableDeferredFreeThreadWithCallback(base::Bind(
      &BlockHeapManager::DeferredFreeDoWork, base::Unretained(this)));
}

void BlockHeapManager::DisableDeferredFreeThread() {
  DCHECK(IsDeferredFreeThreadRunning());

  // Reset |deferred_free_thread_| which disables the features. This is done
  // before stopping the feature as to avoid locking |deferred_free_thread_old|
  // while joining the thread, which can lead to a deadlock. The old value is
  // preserved as it is needed to stop the thread.
  std::unique_ptr<DeferredFreeThread> deferred_free_thread_old;
  {
    base::AutoLock lock(deferred_free_thread_lock_);
    deferred_free_thread_old.swap(deferred_free_thread_);
  }

  // Stop the thread and wait for it to exit.
  if (deferred_free_thread_old)
    deferred_free_thread_old->Stop();

  // Set the overbudget size to 0 to remove the hysteresis.
  shared_quarantine_.SetOverbudgetSize(0);
}

bool BlockHeapManager::IsDeferredFreeThreadRunning() {
  base::AutoLock lock(deferred_free_thread_lock_);
  return deferred_free_thread_ != nullptr;
}

HeapType BlockHeapManager::GetHeapTypeUnlocked(HeapId heap_id) {
  DCHECK(initialized_);
  DCHECK(IsValidHeapIdUnlocked(heap_id, true));
  BlockHeapInterface* heap = GetHeapFromId(heap_id);
  return heap->GetHeapType();
}

bool BlockHeapManager::DestroyHeapContents(
    BlockHeapInterface* heap,
    BlockQuarantineInterface* quarantine) {
  DCHECK(initialized_);
  DCHECK_NE(static_cast<BlockHeapInterface*>(nullptr), heap);
  DCHECK_NE(static_cast<BlockQuarantineInterface*>(nullptr), quarantine);

  // Starts by removing all the block from this heap from the quarantine.
  BlockQuarantineInterface::ObjectVector blocks_vec;

  // We'll keep the blocks that don't belong to this heap in a temporary list.
  // While this isn't optimal in terms of performance, destroying a heap isn't a
  // common operation.
  // TODO(sebmarchand): Add a version of the ShardedBlockQuarantine::Empty
  //     method that accepts a functor to filter the blocks to remove.
  BlockQuarantineInterface::ObjectVector blocks_to_reinsert;
  quarantine->Empty(&blocks_vec);

  for (const auto& iter_block : blocks_vec) {
    BlockInfo expanded = {};
    ConvertBlockInfo(iter_block, &expanded);

    if (enable_page_protections_) {
      // Remove protection to enable access to the block header.
      BlockProtectNone(expanded, shadow_);
    }

    BlockHeapInterface* block_heap = GetHeapFromId(expanded.trailer->heap_id);

    if (block_heap == heap) {
      FreeBlock(iter_block);
    } else {
      blocks_to_reinsert.push_back(iter_block);
    }
  }

  // Restore the blocks that don't belong to this quarantine.
  for (const auto& iter_block : blocks_to_reinsert) {
    BlockInfo expanded = {};
    ConvertBlockInfo(iter_block, &expanded);

    BlockQuarantineInterface::AutoQuarantineLock quarantine_lock(quarantine,
                                                                 iter_block);
    if (quarantine->Push(iter_block).push_successful) {
      if (enable_page_protections_) {
        // Restore protection to quarantined block.
        BlockProtectAll(expanded, shadow_);
      }
    } else {
      // Avoid memory leak.
      FreeBlock(iter_block);
    }
  }

  return true;
}

void BlockHeapManager::DestroyHeapResourcesUnlocked(
    BlockHeapInterface* heap,
    BlockQuarantineInterface* quarantine) {
  // If the heap has an underlying heap then free it as well.
  {
    auto iter = underlying_heaps_map_.find(heap);
    if (iter != underlying_heaps_map_.end()) {
      DCHECK_NE(static_cast<HeapInterface*>(nullptr), iter->second);
      delete iter->second;
      underlying_heaps_map_.erase(iter);
    }
  }

  delete heap;
}

void BlockHeapManager::TrimQuarantine(TrimColor stop_color,
                                      BlockQuarantineInterface* quarantine) {
  DCHECK(initialized_);
  DCHECK_NE(static_cast<BlockQuarantineInterface*>(nullptr), quarantine);

  // Trim the quarantine to the required color.
  if (parameters_.quarantine_size == 0) {
    BlockQuarantineInterface::ObjectVector blocks_to_free;
    quarantine->Empty(&blocks_to_free);
    for (const auto& block : blocks_to_free)
      FreeBlock(block);
  } else {
    CompactBlockInfo compact = {};
    while (true) {
      PopResult result = quarantine->Pop(&compact);
      if (!result.pop_successful)
        break;
      FreeBlock(compact);
      if (result.trim_color <= stop_color)
        break;
    }
  }
}

void BlockHeapManager::FreeBlock(const BlockQuarantineInterface::Object& obj) {
  BlockInfo expanded = {};
  ConvertBlockInfo(obj, &expanded);
  CHECK(FreePotentiallyCorruptBlock(&expanded));
}

namespace {

// A tiny helper function that checks if a quarantined filled block has a valid
// body. If the block is not of that type simply always returns true.
bool BlockBodyIsValid(const BlockInfo& block_info) {
  if (block_info.header->state != QUARANTINED_FLOODED_BLOCK)
    return true;
  if (BlockBodyIsFloodFilled(block_info))
    return true;
  return false;
}

}  // namespace

bool BlockHeapManager::FreePotentiallyCorruptBlock(BlockInfo* block_info) {
  DCHECK(initialized_);
  DCHECK_NE(static_cast<BlockInfo*>(nullptr), block_info);

  if (enable_page_protections_)
    BlockProtectNone(*block_info, shadow_);

  if (block_info->header->magic != kBlockHeaderMagic ||
      !BlockChecksumIsValid(*block_info) ||
      !BlockBodyIsValid(*block_info)) {
    if (ShouldReportCorruptBlock(block_info))
      ReportHeapError(block_info->header, CORRUPT_BLOCK);
    return FreeCorruptBlock(block_info);
  } else {
    return FreePristineBlock(block_info);
  }
}

bool BlockHeapManager::FreeCorruptBlock(BlockInfo* block_info) {
  DCHECK(initialized_);
  DCHECK_NE(static_cast<BlockInfo*>(nullptr), block_info);
  ClearCorruptBlockMetadata(block_info);

  // ClearCorruptBlockMetadata couldn't figure out which heap owns this block.
  // Explode, as there's no way to safely move forward here. Note that the only
  // way to get here is if ReportCorruptBlock decided it didn't want to report
  // this block earlier, and decided to move forward in trying to free it.
  // TODO(chrisha): Entertain the idea of keeping track of such blocks, and
  //     simply reporting them en masse when things finally do go south, or at
  //     process termination.
  if (block_info->trailer->heap_id == 0)
    ReportHeapError(block_info->body, CORRUPT_BLOCK);

  // At this point there's very high confidence that the heap_id is valid so
  // go ahead and try to free the block like normal.
  return FreePristineBlock(block_info);
}

bool BlockHeapManager::FreePristineBlock(BlockInfo* block_info) {
  DCHECK(initialized_);
  DCHECK_NE(static_cast<BlockInfo*>(nullptr), block_info);
  BlockHeapInterface* heap = GetHeapFromId(block_info->trailer->heap_id);

  if (enable_page_protections_) {
    // Remove block protections so the redzones may be modified.
    BlockProtectNone(*block_info, shadow_);
  }

  // Return pointers to the stacks for reference counting purposes.
  if (block_info->header->alloc_stack != nullptr) {
    stack_cache_->ReleaseStackTrace(block_info->header->alloc_stack);
    block_info->header->alloc_stack = nullptr;
  }
  if (block_info->header->free_stack != nullptr) {
    stack_cache_->ReleaseStackTrace(block_info->header->free_stack);
    block_info->header->free_stack = nullptr;
  }

  block_info->header->state = FREED_BLOCK;

  if ((heap->GetHeapFeatures() &
       HeapInterface::kHeapReportsReservations) != 0) {
    shadow_->Poison(block_info->header,
                    block_info->block_size,
                    kAsanReservedMarker);
  } else {
    shadow_->Unpoison(block_info->header, block_info->block_size);
  }
  return heap->FreeBlock(*block_info);
}

bool BlockHeapManager::FreeUnguardedAlloc(HeapId heap_id, void* alloc) {
  DCHECK(initialized_);
  DCHECK(IsValidHeapId(heap_id, false));
  BlockHeapInterface* heap = GetHeapFromId(heap_id);

  // Check if the allocation comes from the process heap.
  if (heap == process_heap_) {
    // The shadow memory associated with this allocation is already green, so
    // no need to modify it.
    return ::HeapFree(::GetProcessHeap(), 0, alloc) == TRUE;
  }

  // If the heap carves greenzones out of redzones, then color the allocation
  // red again. Otherwise, simply leave it green.
  if ((heap->GetHeapFeatures() &
       HeapInterface::kHeapReportsReservations) != 0) {
    DCHECK_NE(0U, heap->GetHeapFeatures() &
                  HeapInterface::kHeapSupportsGetAllocationSize);
    shadow_->Poison(alloc, Size(heap_id, alloc), kAsanReservedMarker);
  }

  return heap->Free(alloc);
}

void BlockHeapManager::ClearCorruptBlockMetadata(BlockInfo* block_info) {
  DCHECK(initialized_);
  DCHECK_NE(static_cast<BlockInfo*>(nullptr), block_info);
  DCHECK_NE(static_cast<BlockHeader*>(nullptr), block_info->header);

  // Set the invalid stack captures to nullptr.
  if (!stack_cache_->StackCapturePointerIsValid(
      block_info->header->alloc_stack)) {
    block_info->header->alloc_stack = nullptr;
  }
  if (!stack_cache_->StackCapturePointerIsValid(
      block_info->header->free_stack)) {
    block_info->header->free_stack = nullptr;
  }

  block_info->trailer->heap_id = GetCorruptBlockHeapId(block_info);
}

void BlockHeapManager::ReportHeapError(void* address, BadAccessKind kind) {
  DCHECK(initialized_);
  DCHECK_NE(static_cast<void*>(nullptr), address);

  // Collect information about the error.
  AsanErrorInfo error_info = {};
  ::RtlCaptureContext(&error_info.context);
  error_info.access_mode = agent::asan::ASAN_UNKNOWN_ACCESS;
  error_info.location = address;
  error_info.error_type = kind;
  ErrorInfoGetBadAccessInformation(shadow_, stack_cache_, &error_info);
  agent::common::StackCapture stack;
  stack.InitFromStack();
  error_info.crash_stack_id = stack.relative_stack_id();

  // We expect a callback to be set.
  DCHECK(!heap_error_callback_.is_null());
  heap_error_callback_.Run(&error_info);
}

void BlockHeapManager::InitInternalHeap() {
  DCHECK_EQ(static_cast<HeapInterface*>(nullptr), internal_heap_.get());
  DCHECK_EQ(static_cast<HeapInterface*>(nullptr),
            internal_win_heap_.get());

  internal_win_heap_.reset(new heaps::WinHeap);
  internal_heap_.reset(
      new heaps::InternalHeap(memory_notifier_, internal_win_heap_.get()));
}

void BlockHeapManager::InitProcessHeap() {
  DCHECK_EQ(static_cast<BlockHeapInterface*>(nullptr), process_heap_);
  process_heap_underlying_heap_ = new heaps::WinHeap(::GetProcessHeap());
  process_heap_ = new heaps::SimpleBlockHeap(process_heap_underlying_heap_);
  underlying_heaps_map_.insert(std::make_pair(process_heap_,
                                              process_heap_underlying_heap_));
  HeapMetadata heap_metadata = { &shared_quarantine_, false };
  auto result = heaps_.insert(std::make_pair(process_heap_, heap_metadata));
  process_heap_id_ = GetHeapId(result);
}

bool BlockHeapManager::MayUseLargeBlockHeap(size_t bytes) const {
  DCHECK(initialized_);
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
  DCHECK(initialized_);
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

bool BlockHeapManager::ShouldReportCorruptBlock(const BlockInfo* block_info) {
  DCHECK_NE(static_cast<const BlockInfo*>(nullptr), block_info);

  if (!parameters_.prevent_duplicate_corruption_crashes)
    return true;

  if (!corrupt_block_registry_cache_.get())
    return true;

  // At this point none of the block content can be trusted, so proceed with
  // extreme caution.
  const common::StackCapture* alloc_stack = block_info->header->alloc_stack;
  if (!stack_cache_->StackCapturePointerIsValid(alloc_stack))
    return true;

  StackId relative_alloc_stack_id = alloc_stack->relative_stack_id();

  // Look at the registry cache to see if an error has already been reported
  // for this allocation stack trace, if so prevent from reporting another one.
  if (corrupt_block_registry_cache_->DoesIdExist(relative_alloc_stack_id))
    return false;

  // Update the corrupt block registry cache to prevent from crashing if we
  // encounter a corrupt block that has the same allocation stack trace.
  corrupt_block_registry_cache_->AddOrUpdateStackId(relative_alloc_stack_id);

  return true;
}

void BlockHeapManager::TrimOrScheduleIfNecessary(
    TrimStatus trim_status,
    BlockQuarantineInterface* quarantine) {
  // If no trimming is required, nothing to do.
  if (trim_status == TRIM_NOT_REQUIRED)
    return;

  // If the deferred thread is not running, always trim synchronously.
  if (!IsDeferredFreeThreadRunning()) {
    TrimQuarantine(TrimColor::YELLOW, quarantine);
    return;
  }

  // Signal the deferred thread to wake up and/or trim synchronously, as needed.
  if (trim_status & TrimStatusBits::ASYNC_TRIM_REQUIRED)
    DeferredFreeThreadSignalWork();
  if (trim_status & TrimStatusBits::SYNC_TRIM_REQUIRED)
    TrimQuarantine(TrimColor::YELLOW, quarantine);
}

void BlockHeapManager::DeferredFreeThreadSignalWork() {
  DCHECK(IsDeferredFreeThreadRunning());
  base::AutoLock lock(deferred_free_thread_lock_);
  deferred_free_thread_->SignalWork();
}

void BlockHeapManager::DeferredFreeDoWork() {
  DCHECK_EQ(GetDeferredFreeThreadId(), base::PlatformThread::CurrentId());
  // As of now, only the shared quarantine gets trimmed asynchronously. This
  // will bring it back in the GREEN color.
  BlockQuarantineInterface* shared_quarantine = &shared_quarantine_;
  TrimQuarantine(TrimColor::GREEN, shared_quarantine);
}

base::PlatformThreadId BlockHeapManager::GetDeferredFreeThreadId() {
  DCHECK(IsDeferredFreeThreadRunning());
  base::AutoLock lock(deferred_free_thread_lock_);
  return deferred_free_thread_->deferred_free_thread_id();
}

void BlockHeapManager::EnableDeferredFreeThreadWithCallback(
    DeferredFreeThread::Callback deferred_free_callback) {
  DCHECK(!IsDeferredFreeThreadRunning());

  shared_quarantine_.SetOverbudgetSize(
      shared_quarantine_.max_quarantine_size() * kOverbudgetSizePercentage /
      100);

  // Create the thread and wait for it to start.
  base::AutoLock lock(deferred_free_thread_lock_);
  deferred_free_thread_.reset(new DeferredFreeThread(deferred_free_callback));
  deferred_free_thread_->Start();
}

HeapId BlockHeapManager::GetCorruptBlockHeapId(const BlockInfo* block_info) {
  base::AutoLock lock(lock_);

  // Check the heap specified in the trailer first.
  bool trailer_has_valid_heap_id = false;
  if (block_info->trailer->heap_id != 0) {
    for (auto hq = heaps_.begin(); hq != heaps_.end(); ++hq) {
      HeapId heap_id = GetHeapId(hq);
      if (heap_id == block_info->trailer->heap_id) {
        if ((hq->first->GetHeapFeatures() &
                 BlockHeapInterface::kHeapSupportsIsAllocated) == 0) {
          // If the trailer heap id is valid but the heap doesn't support
          // IsAllocated then remember this as a backup answer for later.
          trailer_has_valid_heap_id = true;
        } else {
          // If the advertised heap can be confirmed to own this block then
          // return that heap id.
          if (hq->first->IsAllocated(block_info->header))
            return heap_id;
        }

        break;
      }
    }
  }

  // These keep track of heaps that don't support IsAllocated in the loop
  // below.
  HeapId unsupported_heap_id = 0;
  size_t unsupported_heap_count = 0;

  // Check against every outstanding heap.
  for (auto hq = heaps_.begin(); hq != heaps_.end(); ++hq) {
    HeapId heap_id = GetHeapId(hq);

    // Skip heaps that don't support IsAllocated.
    if ((hq->first->GetHeapFeatures() &
            BlockHeapInterface::kHeapSupportsIsAllocated) == 0) {
      unsupported_heap_id = heap_id;
      ++unsupported_heap_count;
      continue;
    }

    if (hq->first->IsAllocated(block_info->header))
      return heap_id;
  }

  // If no heap was found but only a single heap doesn't support
  // IsAllocated, then that's the heap by process of elimination.
  if (unsupported_heap_count == 1)
    return unsupported_heap_id;

  // If the trailer contained a valid heap ID but it simply couldn't be
  // confirmed to be owner of the block then assume that's the heap.
  if (trailer_has_valid_heap_id)
    return block_info->trailer->heap_id;

  // Unfortunately, there's no way to know which heap this block belongs to.
  return 0;
}

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent
