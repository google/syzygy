// Copyright 2011 Google Inc.
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
#ifndef SYZYGY_REORDER_LINEAR_ORDER_GENERATOR_H_
#define SYZYGY_REORDER_LINEAR_ORDER_GENERATOR_H_

#include "syzygy/reorder/reorderer.h"

namespace reorder {

// A simple linear order generator. See comment at top of this header file for
// more details.
class LinearOrderGenerator : public Reorderer::OrderGenerator {
 public:
  typedef Reorderer::UniqueTime UniqueTime;
  typedef Reorderer::Order Order;

  LinearOrderGenerator();
  virtual ~LinearOrderGenerator();

  // OrderGenerator implementation.
  virtual bool OnCodeBlockEntry(const Reorderer& reorderer,
                                const BlockGraph::Block* block,
                                RelativeAddress address,
                                uint32 process_id,
                                uint32 thread_id,
                                const UniqueTime& time);
  virtual bool CalculateReordering(const Reorderer& reorderer,
                                   Order* order);

 private:
  typedef std::map<const BlockGraph::Block*, UniqueTime> BlockCallMap;

  // Called by OnFunctionEntry to update block_calls_.
  bool TouchBlock(const BlockGraph::Block* block, const UniqueTime& time);
  // Given a code block, touches the data blocks associated with it.
  bool TouchDataBlocks(const BlockGraph::Block* code_block,
                       const UniqueTime& time);

  // Stores pointers to blocks, and the first time at which they were accessed.
  BlockCallMap block_calls_;
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_LINEAR_ORDER_GENERATOR_H_
