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
#ifndef SYZYGY_REORDER_DEAD_CODE_FINDER_H_
#define SYZYGY_REORDER_DEAD_CODE_FINDER_H_

#include "syzygy/reorder/reorderer.h"
#include <set>

namespace reorder {

// Identifies code symbols which are not referenced by a given call trace.
class DeadCodeFinder : public Reorderer::OrderGenerator {
 public:
  typedef Reorderer::UniqueTime UniqueTime;
  typedef Reorderer::Order Order;
  typedef BlockGraph::AddressSpace AddressSpace;
  typedef BlockGraph::Block Block;

  DeadCodeFinder();
  virtual ~DeadCodeFinder();

 private:
  DISALLOW_COPY_AND_ASSIGN(DeadCodeFinder);

  // Returns true if the block is of interest and unvisited.
  bool IsDead(const Block* block) const;

  // OrderGenerator implementation.
  virtual bool OnCodeBlockEntry(const Reorderer& reorderer,
                                const Block* block,
                                RelativeAddress address,
                                uint32 process_id,
                                uint32 thread_id,
                                const UniqueTime& time);
  virtual bool CalculateReordering(const Reorderer& reorderer,
                                   Order* order);

   std::set<const Block*> visited_blocks_;
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_DEAD_CODE_FINDER_H_
