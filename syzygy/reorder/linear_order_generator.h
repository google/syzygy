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
// An implementation of a Reorderer. The LinearOrderGenerator simply orders code
// blocks in the order that they were executed as seen in the call-trace.
// If data ordering is enabled, all data blocks referred to by a code block
// are assumed to have been touched when the code block was executed, and they
// are output in that order.
//
// If multiple runs of the instrumented binary are seen in the trace files, each
// run will be processed independently, and for each unique block, the count of
// how many runs in which its execution was seen is maintained. Blocks are first
// sorted by the number of individual runs in which they were seen (decreasing),
// and then sorted by the order in which they were seen. For the special case
// of blocks that were only seen in a single run of the binary, these are
// separated by run and then sorted by time seen.
//
// Consider a trace file that contains 3 runs of an executable. The generated
// ordering will be as follows:
//
// code seen in all 3 runs, code seen in any 2 runs, code seen only in 1st run,
//     code seen only in 2nd run, code seen only in 3rd run
//
// In the case where there is a single run of the instrumented binary, the
// ordering will be a simple ordering of blocks by order of execution, as per
// our original proof-of-concept ordering.

#ifndef SYZYGY_REORDER_LINEAR_ORDER_GENERATOR_H_
#define SYZYGY_REORDER_LINEAR_ORDER_GENERATOR_H_

#include <map>
#include <set>
#include <vector>

#include "syzygy/reorder/reorderer.h"

namespace reorder {

// A simple linear order generator. See comment at top of this header file for
// more details.
class LinearOrderGenerator : public Reorderer::OrderGenerator {
 public:
  struct BlockCall;

  LinearOrderGenerator();
  virtual ~LinearOrderGenerator();

  // OrderGenerator implementation.
  virtual bool OnProcessStarted(uint32 process_id,
                                const UniqueTime& time) OVERRIDE;
  virtual bool OnProcessEnded(uint32 process_id,
                              const UniqueTime& time) OVERRIDE;
  virtual bool OnCodeBlockEntry(const BlockGraph::Block* block,
                                RelativeAddress address,
                                uint32 process_id,
                                uint32 thread_id,
                                const UniqueTime& time) OVERRIDE;
  virtual bool CalculateReordering(const PEFile& pe_file,
                                   const ImageLayout& image,
                                   bool reorder_code,
                                   bool reorder_data,
                                   Order* order) OVERRIDE;

 private:
  typedef std::vector<BlockCall> BlockCalls;
  typedef std::map<size_t, BlockCalls> ProcessGroupBlockCalls;
  typedef std::map<const BlockGraph::Block*, BlockCall> BlockCallMap;
  typedef std::set<const BlockGraph::Block*> BlockSet;

  // Called by OnFunctionEntry to update block_calls_.
  bool TouchBlock(const BlockCall& block_call);

  // Given a block, inserts the data blocks associated with it into
  // the ordering. Will recursively traverse data blocks until the given
  // maximum stack depth (that way, we include data referred to by data).
  bool InsertDataBlocks(size_t max_recursion_depth,
                        const BlockGraph::Block* block,
                        Order* order,
                        BlockSet* inserted_blocks);

  // This is called to indicate a process group closure.
  bool CloseProcessGroup();

  // We assume that processes that co-exist are all part of a single run.
  // So we divide up block calls per run. This counts the number of currently
  // active processes, and when it reaches zero it means that we need to
  // start a new process.
  size_t active_process_count_;

  // This is for creating unique ids for groups of coexisting processes.
  // This is incremented every time active_process_count transitions from 0
  // to 1.
  size_t next_process_group_id_;

  // Stores the linearized block list per process group.
  ProcessGroupBlockCalls process_group_calls_;

  // Stores pointers to blocks, and the first time at which they were accessed.
  // There is one of these per 'process group'.
  BlockCallMap block_call_map_;
};

struct LinearOrderGenerator::BlockCall {
  const BlockGraph::Block* block;
  uint32 process_id;
  uint32 thread_id;
  UniqueTime time;

  BlockCall(const BlockGraph::Block* block, uint32 process_id,
            uint32 thread_id, const UniqueTime& time)
      : block(block), process_id(process_id), thread_id(thread_id),
        time(time) {
  }
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_LINEAR_ORDER_GENERATOR_H_
