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

#include <unordered_map>

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/agent/asan/block_utils.h"
#include "syzygy/agent/asan/heap.h"
#include "syzygy/agent/asan/heap_manager.h"
#include "syzygy/agent/asan/quarantine.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/agent/asan/quarantines/sharded_quarantine.h"
#include "syzygy/common/asan_parameters.h"

namespace agent {
namespace asan {
namespace heap_managers {

// A block heap manager is an implementation of a heap manager that allocates
// and manages blocks.
//
// It is responsible for maintaining the state of the shadow memory, and thus
// updating it when a block's state changes. This also takes care of maintaining
// a quarantine of freed blocks.
//
// When the user requests a new heap he will receive a pointer to a
// SimpleBlockHeap by default. However the goal of this manager is to
// automatically choose the most appropriate heap for a given allocation so the
// actual heap that serves an allocation can be different from the one returned
// to the user.
//
// TODO(sebmarchand): Plug in other heaps, like the zebra heap and the large
//     block heap.
// TODO(sebmarchand): Bring in the HeapErrorCallback mechanism as declared
//     in HeapProxy and use it to report the heap related errors.
// TODO(sebmarchand): Add page protection support.
class BlockHeapManager : public HeapManagerInterface {
 public:
  // Constructor.
  // @param logger The logger that will be used to report the errors.
  explicit BlockHeapManager(AsanLogger* logger);

  // Destructor.
  virtual ~BlockHeapManager();

  // @name HeapManagerInterface functions.
  // @{
  virtual HeapId CreateHeap();
  virtual bool DestroyHeap(HeapId heap_id);
  virtual void* Allocate(HeapId heap_id, size_t bytes);
  virtual bool Free(HeapId heap_id, void* alloc);
  virtual size_t Size(HeapId heap_id, void* alloc);
  virtual void Lock(HeapId heap_id);
  virtual void Unlock(HeapId heap_id);
  // @}

  // Set the parameters of this heap manager.
  // @param trailer_padding_size The trailer padding size, in bytes.
  void set_parameters(const common::AsanParameters& parameters);

  // Get the parameters.
  common::AsanParameters parameters() {
    return parameters_;
  }

 protected:
  // The type of quarantine that we use internally.
  typedef quarantines::ShardedQuarantine<BlockHeader*,
                                         GetTotalBlockSizeFunctor,
                                         GetBlockHashFunctor,
                                         kQuarantineDefaultShardingFactor>
      ShardedBlockQuarantine;

  // A map associating a block heap with its underlying heap.
  typedef std::unordered_map<BlockHeapInterface*, HeapInterface*>
      UnderlyingHeapMap;

  // A map associating a block heap with the quarantine it will use. Many heaps
  // may share a single quarantine.
  typedef std::unordered_map<BlockHeapInterface*, ShardedBlockQuarantine*>
      HeapQuarantineMap;

  // Propagates the parameters to the appropriate modules.
  // @note This function is responsible for acquiring lock_ when necessary.
  void PropagateParameters();

  // Destroy a heap and flush its quarantine. If this heap has an underlying
  // heap it'll also destroy it. All the block belonging to this heap that are
  // in the quarantine will be freed.
  //
  // @param heap The heap to destroy.
  // @param quarantine The quarantine of this heap.
  // @returns true on success, false otherwise.
  // @note The heap pointer will be invalid if this function succeeds.
  // @note This must be called under lock_.
  bool DestroyHeapUnlocked(BlockHeapInterface* heap,
                           ShardedBlockQuarantine* quarantine);

  // If the quarantine of a heap is over its maximum size, trim it down until
  // it's below the limit.
  // @param quarantine The quarantine to trim.
  void TrimQuarantine(ShardedBlockQuarantine* quarantine);

  // Free an allocated block. This should be called when a block is removed from
  // the quarantine or directly freed. This takes care of updating the shadow
  // memory and releasing the resources acquired by this block (like its stack
  // traces).
  // @param header The header of this block.
  // @returns true on success, false otherwise.
  bool FreeBlock(BlockHeader* header);

  // A repository of unique stack captures recorded on alloc and free.
  StackCaptureCache stack_cache_;

  // Protects concurrent access to the heap manager internals.
  base::Lock lock_;

  // Contains the heaps owned by this manager.
  HeapQuarantineMap heaps_;  // Under lock_.

  // The quarantine shared by the heaps created by this manager.
  ShardedBlockQuarantine shared_quarantine_;

  // Map the block heaps to their underlying heap.
  UnderlyingHeapMap underlying_heaps_map_;  // Under lock_.

  // The parameters of this heap manager.
  common::AsanParameters parameters_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BlockHeapManager);
};

}  // namespace heap_managers
}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_HEAP_MANAGERS_BLOCK_HEAP_MANAGER_H_
