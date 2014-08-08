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

#ifndef SYZYGY_REORDER_BASIC_BLOCK_OPTIMIZER_H_
#define SYZYGY_REORDER_BASIC_BLOCK_OPTIMIZER_H_

#include <string>

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_transform_policy.h"
#include "syzygy/reorder/reorderer.h"

namespace reorder {

// A class to optimize the basic-block placement of a block ordering, given
// basic-block entry count data.
class BasicBlockOptimizer {
 public:
  typedef grinder::basic_block_util::IndexedFrequencyInformation
      IndexedFrequencyInformation;
  typedef pe::ImageLayout ImageLayout;
  typedef Reorderer::Order Order;

  // A helper class with utility functions used by the optimization functions.
  // Exposed as public to facilitate unit-testing.
  class BasicBlockOrderer;

  // Constructor.
  BasicBlockOptimizer();

  // @returns the name that will be assigned to the cold block section.
  const std::string& cold_section_name() const { return cold_section_name_; }

  // Set the name that will be assigned to the cold block section.
  void set_cold_section_name(const base::StringPiece& value) {
    DCHECK(!value.empty());
    value.CopyToString(&cold_section_name_);
  }

  // Basic-block optimize the given @p order.
  bool Optimize(const ImageLayout& image_layout,
                const IndexedFrequencyInformation& entry_counts,
                Order* order);

 protected:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::ConstBlockVector ConstBlockVector;

  // Optimize the layout of all basic-blocks in a block.
  static bool OptimizeBlock(const pe::PETransformPolicy& policy,
                            const BlockGraph::Block* block,
                            const ImageLayout& image_layout,
                            const IndexedFrequencyInformation& entry_counts,
                            Order::BlockSpecVector* warm_block_specs,
                            Order::BlockSpecVector* cold_block_specs);

  // Optimize the layout of all basic-blocks in a section, as defined by the
  // given @p section_spec and the original @p image_layout.
  static bool OptimizeSection(const pe::PETransformPolicy& policy,
                              const ImageLayout& image_layout,
                              const IndexedFrequencyInformation& entry_counts,
                              const ConstBlockVector& explicit_blocks,
                              Order::SectionSpec* orig_section_spec,
                              Order::BlockSpecVector* warm_block_specs,
                              Order::BlockSpecVector* cold_block_specs);

  // The name of the (new) section in which to place cold blocks and
  // basic-blocks.
  std::string cold_section_name_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockOptimizer);
};

// A helper class which generates warm and cold basic-block orderings for
// a given basic-block subgraph.
class BasicBlockOptimizer::BasicBlockOrderer {
 public:
  typedef block_graph::BasicBlock BasicBlock;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef block_graph::BasicDataBlock BasicDataBlock;
  typedef std::set<const BasicBlock*> BasicBlockSet;
  typedef BlockGraph::Offset Offset;
  typedef BlockGraph::Size Size;
  typedef grinder::basic_block_util::EntryCountType EntryCountType;
  typedef grinder::basic_block_util::IndexedFrequencyInformation
      IndexedFrequencyInformation;
  typedef grinder::basic_block_util::RelativeAddress RelativeAddress;

  BasicBlockOrderer(const BasicBlockSubGraph& subgraph,
                    const RelativeAddress& addr,
                    Size size,
                    const IndexedFrequencyInformation& entry_counts);

  // Get the number of times the block itself was entered. This assumes that
  // the entry point of the block is its first basic block.
  bool GetBlockEntryCount(EntryCountType* entry_count) const;

  // Generate an ordered list or warm and cold basic blocks. The warm basic-
  // blocks are ordered such that branches are straightened for the most common
  // successor. The cold basic-blocks are maintained in their original ordering
  // in the block.
  bool GetBasicBlockOrderings(Order::OffsetVector* warm_basic_blocks,
                              Order::OffsetVector* cold_basic_blocks) const;

 protected:
  // Get the number of times a given code basic-block was entered.
  bool GetBasicBlockEntryCount(const BasicCodeBlock* code_bb,
                               EntryCountType* entry_count) const;

  // Get the warmest not-yet-placed successor to the given code basic-block.
  // This may yield a NULL pointer, denoting either no successor, or no not-
  // yet-placed successor.
  bool GetWarmestSuccessor(const BasicCodeBlock* code_bb,
                           const BasicBlockSet& placed_bbs,
                           const BasicBlock** succ_bb) const;

  // Get the collection of the targets referenced from a given jmp instruction
  // sorted in order of decreasing entry count (i.e., highest entry count
  // first). Note that the sort is stable, targets having the same entry counts
  // are returned in the same relative order as originally in the jump table.
  bool GetSortedJumpTargets(const block_graph::Instruction& jmp_inst,
                            std::vector<const BasicCodeBlock*>* targets) const;

  // Add all data basic-blocks referenced from @p code_bb to @p warm_references.
  bool AddWarmDataReferences(const BasicCodeBlock* code_bb,
                             BasicBlockSet* warm_references) const;

  // Recursively add @p data_bb and all data basic-blocks referenced by
  // @p data_bb to @p warm references.
  void AddRecursiveDataReferences(const BasicDataBlock* data_bb,
                                  BasicBlockSet* warm_references) const;

 protected:
  const BasicBlockSubGraph& subgraph_;
  const RelativeAddress& addr_;
  const Size size_;
  const IndexedFrequencyInformation& entry_counts_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockOrderer);
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_BASIC_BLOCK_OPTIMIZER_H_
