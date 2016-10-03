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
// Implementation of a heap manager that allocates blocks.

#ifndef SYZYGY_AGENT_ASAN_HEAP_MANAGERS_BLOCK_HEAP_MANAGER_H_
#define SYZYGY_AGENT_ASAN_HEAP_MANAGERS_BLOCK_HEAP_MANAGER_H_

#include <windows.h>

#include <memory>
#include <unordered_map>
#include <utility>

#include "base/logging.h"
#include "syzygy/agent/asan/block_utils.h"
#include "syzygy/agent/asan/error_info.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/heap_manager.h"
#include "syzygy/agent/asan/quarantine.h"
#include "syzygy/agent/asan/registry_cache.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/asan/heap_managers/deferred_free_thread.h"
#include "syzygy/agent/asan/memory_notifiers/shadow_memory_notifier.h"
#include "syzygy/agent/asan/quarantines/sharded_quarantine.h"
#include "syzygy/agent/common/stack_capture.h"
#include "syzygy/common/asan_parameters.h"

namespace agent {
namespace asan {

// Forward declarations
namespace heaps {

class ZebraBlockHeap;

}  // namespace heaps

namespace heap_managers {

// A block heap manager is an implementation of a heap manager that allocates
// and manages blocks.
//
// It is responsible for maintaining the state of the shadow memory, and thus
// updating it when a block's state changes. This also takes care of maintaining
// a quarantine of freed blocks.
//
// When the user requests a new heap, it will receive a pointer to a
// SimpleBlockHeap by default. However the goal of this manager is to
// automatically choose the most appropriate heap for a given allocation so the
// actual heap that serves an allocation can be different from the one returned
// to the user.
//
// The zebra heap is created once, when enabled for the first time, with a
// specified size. It can't be resized after creation. Disabling the zebra
// heap only disables allocations on it, deallocations will continue to work.
class BlockHeapManager : public HeapManagerInterface {
 public:
  // Constructor.
  // @param shadow The shadow memory to use.
  // @param stack_cache The stack cache to use.
  // @param memory_notifier The memory notifier to use.
  BlockHeapManager(Shadow* shadow,
                   StackCaptureCache* stack_cache,
                   MemoryNotifierInterface* memory_notifier);

  // Destructor.
  virtual ~BlockHeapManager();

  // Initializes this block heap manager. Must be called prior to any
  // HeapManagerInterface functions. Parameters may be set prior to this.
  void Init();

  // @name HeapManagerInterface functions.
  // @{
   HeapId CreateHeap() override;
   bool DestroyHeap(HeapId heap_id) override;
   void* Allocate(HeapId heap_id, uint32_t bytes) override;
   bool Free(HeapId heap_id, void* alloc) override;
   uint32_t Size(HeapId heap_id, const void* alloc) override;
   void Lock(HeapId heap_id) override;
   void Unlock(HeapId heap_id) override;
   void BestEffortLockAll() override;
   void UnlockAll() override;
  // @}

  // Set the parameters of this heap manager.
  // @param trailer_padding_size The trailer padding size, in bytes.
  void set_parameters(const ::common::AsanParameters& parameters);

  // Get the parameters.
  ::common::AsanParameters parameters() {
    return parameters_;
  }

  // Sets the callback that this heap will invoke when heap corruption is
  // encountered.
  // @param heap_error_callback The callback to be invoked when heap
  //     corruption is encountered.
  void SetHeapErrorCallback(HeapErrorCallback heap_error_callback) {
    heap_error_callback_ = heap_error_callback;
  }

  // Returns the process heap ID.
  HeapId process_heap() { return process_heap_id_; }

  // Returns the allocation-filter flag value.
  // @returns the allocation-filter flag value.
  // @note The flag is stored per-thread using TLS. Multiple threads do not
  //     share the same flag.
  bool allocation_filter_flag() const;

  // Sets the allocation-filter flag to the specified value.
  // @param value the new value for the flag.
  // @note The flag is stored per-thread using TLS. Multiple threads do not
  //     share the same flag.
  void set_allocation_filter_flag(bool value);

  // Enables the deferred free thread mechanism. Must not be called if the
  // thread is already running. Typical usage is to enable the thread at startup
  // and disable it at shutdown.
  void EnableDeferredFreeThread();

  // Disables the deferred free thread mechanism. Must be called before the
  // destructor if the thread is enabled. Must also never be called if the
  // thread is not enabled.
  void DisableDeferredFreeThread();

  // @returns true if the deferred thread is currently running.
  bool IsDeferredFreeThreadRunning();

 protected:
  // This allows the runtime access to our internals, necessary for crash
  // processing.
  friend class AsanRuntime;

  // @name Functions intended for use exclusively by the AsanRuntime for
  //     introspection during crash processing.
  // @{
  HeapType GetHeapTypeUnlocked(HeapId heap_id);
  // @}

  // The type of quarantine that we use internally.
  using ShardedBlockQuarantine =
      quarantines::ShardedQuarantine<CompactBlockInfo,
                                     GetTotalBlockSizeFunctor,
                                     GetBlockHashFunctor,
                                     kQuarantineDefaultShardingFactor>;

  // A map associating a block heap with its underlying heap.
  using UnderlyingHeapMap =
      std::unordered_map<BlockHeapInterface*, HeapInterface*>;

  // A map associating a block heap with a pair containing the quarantine it
  // will use and a bit indicating if it's dying. Many heaps may share a single
  // quarantine.
  struct HeapMetadata {
    BlockQuarantineInterface* quarantine;
    bool is_dying;
  };
  using HeapQuarantineMap =
      std::unordered_map<BlockHeapInterface*, HeapMetadata>;
  using HeapQuarantinePair = BlockHeapManager::HeapQuarantineMap::value_type;

  using StackId = agent::common::StackCapture::StackId;

  // Causes the heap manager to tear itself down. If the heap manager
  // encounters corrupt blocks while tearing itself dow it will report an
  // error. This will in turn cause the asan runtime to call back into itself
  // and access the block heap manager. Thus, the block heap manager needs to
  // still be alive while this process is occurring. Hence, the need to
  // separate the work of tearing down the heap manager from its destructor.
  void TearDownHeapManager();

  // Given the result of an HeapQuarantineMap insert or find, returns a heap id.
  // @param iterator An iterator to a heap.
  // @param insert_result The result of a call to heaps_.insert.
  // @returns the ID associated with the inserted heap.
  HeapId GetHeapId(
      HeapQuarantineMap::iterator iterator) const;
  HeapId GetHeapId(
      const std::pair<HeapQuarantineMap::iterator, bool>& insert_result) const;

  // @name Heap validation. There are multiple ways to do this because of the
  //     need to do this during crash processing, when locks are already
  //     implicitly acquired. As such, the runtime has been made a friend of
  //     this class.
  // Determines if a heap ID is valid.
  // @param heap_id The heap_id to validate.
  // @param allow_dying If true then also consider heaps that are in the
  //     process of dying. Otherwise, only consider live heaps.
  // @returns true if the given heap id is valid.
  // @note The unsafe variants can raise access violations.
  bool IsValidHeapIdUnsafe(HeapId heap_id, bool allow_dying);
  bool IsValidHeapIdUnsafeUnlocked(HeapId heap_id, bool allow_dying);
  bool IsValidHeapId(HeapId heap_id, bool allow_dying);
  bool IsValidHeapIdUnlocked(HeapId heap_id, bool allow_dying);

  // Helpers for the above functions. This is split into two to keep the
  // locking as narrow as possible.
  // @param hq The heap quarantine pair being queried.
  // @param allow_dying If true then also consider heaps that are in the
  //     process of dying. Otherwise, only consider live heaps.
  bool IsValidHeapIdUnsafeUnlockedImpl1(HeapQuarantinePair* hq);
  bool IsValidHeapIdUnlockedImpl1(HeapQuarantinePair* hq);
  bool IsValidHeapIdUnlockedImpl2(HeapQuarantinePair* hq, bool allow_dying);
  // @}

  // Given a heap ID, returns the underlying heap.
  // @param heap_id The ID of the heap to look up.
  // @returns a pointer to the heap implementation.
  // @note DCHECKs on invalid input.
  static BlockHeapInterface* GetHeapFromId(HeapId heap_id);

  // Given a heap ID, returns the associated quarantine.
  // @param heap_id The ID of the heap whose quarantine is to be looked up.
  // @returns a pointer to the quarantine implementation.
  // @note DCHECKs on invalid input.
  static BlockQuarantineInterface* GetQuarantineFromId(HeapId heap_id);

  // Propagates the parameters to the appropriate modules.
  // @note This function is responsible for acquiring lock_ when necessary.
  void PropagateParameters();

  // Destroy a heap and flush its quarantine. If this heap has an underlying
  // heap it'll also destroy it. All the blocks belonging to this heap that are
  // in the quarantine will be freed.
  //
  // @param heap The heap to destroy.
  // @param quarantine The quarantine of this heap.
  // @returns true on success, false otherwise.
  // @note The heap pointer will be invalid if this function succeeds.
  bool DestroyHeapContents(BlockHeapInterface* heap,
                           BlockQuarantineInterface* quarantine);

  // Removes a heap from the manager, then frees it and any resources
  // associated with it. This does not remove the heap pointer from the
  // heaps_ structure.
  // @note This must be called under lock_.
  void DestroyHeapResourcesUnlocked(BlockHeapInterface* heap,
                                    BlockQuarantineInterface* quarantine);

  // Trim the specified quarantine until its color is |stop_color| or lower. If
  // parameters_.quarantine_size is 0 then the quarantine is flushed.
  // @param stop_color The target color at which the trimming ends.
  // @param quarantine The quarantine to trim.
  // TODO(peterssen): Change the 0-size contract. The quarantine 'contract'
  //    establish that when the size is 0, it means unlimited, this is rather
  //    awkward since trimming with size 0 should flush the quarantine.
  void TrimQuarantine(TrimColor stop_color,
                      BlockQuarantineInterface* quarantine);

  // Free a block.
  // @param obj The object to be freed.
  void FreeBlock(const BlockQuarantineInterface::Object& obj);

  // Free a block that might be corrupt. If the block is corrupt first reports
  // an error before safely releasing the block.
  // @param block_info The information about this block.
  // @returns true if the block has been successfully freed, false otherwise.
  bool FreePotentiallyCorruptBlock(BlockInfo* block_info);

  // Free a corrupt block. This takes care of cleaning its metadata before
  // trying to free it.
  // @param block_info The information about this block.
  // @returns true if the block has been successfully freed, false otherwise.
  bool FreeCorruptBlock(BlockInfo* block_info);

  // Free an allocated block. This should be called when a block is removed from
  // the quarantine or directly freed. This takes care of updating the shadow
  // memory and releasing the resources acquired by this block (like its stack
  // traces). The block should either not be corrupt or cleaned from its unsafe
  // metadata.
  // @param block_info The information about this block.
  // @returns true on success, false otherwise.
  bool FreePristineBlock(BlockInfo* block_info);

  // Free an unguarded allocation.
  // @param heap_id A hint about the heap that might contain this allocation.
  // @param alloc The allocation to be freed.
  // @returns true if the allocation has been successfully freed, false
  //     otherwise.
  bool FreeUnguardedAlloc(HeapId heap_id, void* alloc);

  // Clears the metadata of a corrupt block. After calling this function the
  // block can safely be passed to FreeBlock, but only if heap_id is non-zero.
  // @param block_info The information about this block.
  void ClearCorruptBlockMetadata(BlockInfo* block_info);

  // Reports a heap error via the heap error callback. This is for originating
  // errors that are detected while performing operations on a heap metadata.
  // Read/write errors are detected outside of the manager, and query the heap
  // for information about the error itself.
  // @param address The address that was being accessed/manipulating when the
  //     error was detected.
  // @param kind The type of error encountered.
  void ReportHeapError(void* address, BadAccessKind kind);

  // Initializes internal heap structures, if not yet done. This must be called
  // before PropagateParameters and InitProcessHeap.
  void InitInternalHeap();

  // Initialize the process heap. This is only meant to be called at
  // initialization time when process_heap_ is NULL.
  // Exposed for unittesting.
  void InitProcessHeap();

  // Determines if the large block heap should be used for an allocation of
  // the given size.
  // @param bytes The allocation size.
  // @returns true if the large block heap should be used for this allocation,
  //     false otherwise.
  bool MayUseLargeBlockHeap(size_t bytes) const;

  // Determines if the zebra block heap should be used for an allocation of
  // the given size.
  // @param bytes The allocation size.
  // @returns true if the zebra heap should be used for this allocation, false
  //     otherwise.
  bool MayUseZebraBlockHeap(size_t bytes) const;

  // Indicates if a corrupt block error should be reported.
  // @param block_info The corrupt block.
  // @returns true if an error should be reported, false otherwise.
  bool ShouldReportCorruptBlock(const BlockInfo* block_info);

  // Called to check if the quarantine needs to be trimmed. This will either
  // schedule asynchronous trimming, execute synchronous trimming, do both or do
  // neither, depending on the value of |trim_status|.
  // @param quarantine The quarantine to be trimmed.
  // @param trim_status The status returned by the push.
  void TrimOrScheduleIfNecessary(TrimStatus trim_status,
                                 BlockQuarantineInterface* quarantine);

  // Used by TrimOrScheduleIfNecessary to signal the deferred free thread that
  // the quarantine needs trimming (ie. asynchronous trimming).
  void DeferredFreeThreadSignalWork();

  // Invoked by the deferred free thread when it is signaled that the quarantine
  // needs trimming.
  void DeferredFreeDoWork();

  // Implementation of EnableDeferredFreeThread that takes the callback. Used
  // also by tests to override the callback.
  // @param deferred_free_callback The callback.
  void EnableDeferredFreeThreadWithCallback(
      DeferredFreeThread::Callback deferred_free_callback);

  // Returns the ID of the deferred free thread. Must not be called if the
  // thread is not running.
  // @returns the thread ID.
  base::PlatformThreadId GetDeferredFreeThreadId();

  // Helper function for finding the heap ID associated with a corrupt block.
  // This is best effort, and can return 0 when no heap can be found with
  // certainty.
  HeapId GetCorruptBlockHeapId(const BlockInfo* block_info);

  // The shadow memory that is notified by all activity in this heap manager.
  Shadow* shadow_;

  // The stack cache used to store the stack traces.
  StackCaptureCache* stack_cache_;

  // The memory notifier to use.
  MemoryNotifierInterface* memory_notifier_;

  // Protects concurrent access to the heap manager internals.
  base::Lock lock_;

  // Indicates if 'Init' has been called.
  bool initialized_;  // Under lock_.

  // Contains the heaps owned by this manager.
  HeapQuarantineMap heaps_;  // Under lock_.

  // The quarantine shared by the heaps created by this manager. This is also
  // used by the LargeBlockHeap.
  ShardedBlockQuarantine shared_quarantine_;

  // Map the block heaps to their underlying heap.
  UnderlyingHeapMap underlying_heaps_map_;  // Under lock_.

  // The parameters of this heap manager.
  ::common::AsanParameters parameters_;

  // The callback this manager uses to expose internal state errors. These are
  // caused by uninstrumented code (system libraries, etc), thus aren't caught
  // at their source. Catching their side effect as early as possible allows the
  // recovery of some useful debugging information.
  HeapErrorCallback heap_error_callback_;

  // The process heap.
  //
  // TODO(sebmarchand): Put the interception of the process heap behind a flag
  //     and return the original process heap by default.
  BlockHeapInterface* process_heap_;
  HeapInterface* process_heap_underlying_heap_;
  HeapId process_heap_id_;

  // The heap that gets used for allocation of internal data structures.
  std::unique_ptr<HeapInterface> internal_win_heap_;
  std::unique_ptr<HeapInterface> internal_heap_;

  // Hold the single ZebraBlockHeap instance used by this heap manager.
  // The lifetime management of the zebra heap is provided by the
  // HeapQuarantineMap, this is simply a useful pointer for finding the
  // zebra heap directly.
  heaps::ZebraBlockHeap* zebra_block_heap_;
  HeapId zebra_block_heap_id_;

  // The ID of the large block heap. Allows accessing it directly.
  HeapId large_block_heap_id_;

  // Stores the AllocationFilterFlag TLS slot.
  DWORD allocation_filter_flag_tls_;

  // A list of all heaps whose locks were acquired by the last call to
  // BestEffortLockAll. This uses the internal heap, otherwise the default
  // allocator makes use of the process heap. The process heap may itself
  // be locked when we try to use this, hence a deadlock can occur. This ends
  // up being a null terminated array of HeapInterface*.
  // Under lock_.
  HeapInterface** locked_heaps_;

  // Indicates if we use page protection to prevent invalid accesses to a block.
  bool enable_page_protections_;

  // The registry cache that we use to store the allocation stack ID of the
  // corrupt block for which we've already reported an error. This isn't used
  // in processes where registry access is blocked (ie, Chrome renderers).
  std::unique_ptr<RegistryCache> corrupt_block_registry_cache_;

 private:
  // Background thread that takes care of trimming the quarantine
  // asynchronously.
  base::Lock deferred_free_thread_lock_;
  // Under deferred_free_thread_lock_.
  std::unique_ptr<DeferredFreeThread> deferred_free_thread_;

  DISALLOW_COPY_AND_ASSIGN(BlockHeapManager);
};

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAP_MANAGERS_BLOCK_HEAP_MANAGER_H_
