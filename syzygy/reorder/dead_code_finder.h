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
#ifndef SYZYGY_REORDER_DEAD_CODE_FINDER_H_
#define SYZYGY_REORDER_DEAD_CODE_FINDER_H_

#include <set>

#include "syzygy/reorder/reorderer.h"

namespace reorder {

// Identifies code symbols which are not referenced by a given call trace.
class DeadCodeFinder : public Reorderer::OrderGenerator {
 public:
  typedef BlockGraph::Block Block;

  DeadCodeFinder();
  virtual ~DeadCodeFinder();

  // Returns true if the block is of interest and unvisited.
  bool IsDead(const Block* block) const;

  // OrderGenerator implementation.
  // @{
  virtual bool OnCodeBlockEntry(const Block* block,
                                RelativeAddress address,
                                uint32_t process_id,
                                uint32_t thread_id,
                                const UniqueTime& time) override;
  virtual bool CalculateReordering(const PEFile& pe_file,
                                   const ImageLayout& image,
                                   bool reorder_code,
                                   bool reorder_data,
                                   Order* order) override;
  // @}

 protected:
  // The set of blocks observed while reading the call trace.
  std::set<const Block*> visited_blocks_;

 private:
  DISALLOW_COPY_AND_ASSIGN(DeadCodeFinder);
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_DEAD_CODE_FINDER_H_
