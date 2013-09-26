// Copyright 2013 Google Inc. All Rights Reserved.
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
// Implementation of the jump table count instrumentation transform.
//
// The purpose of this instrumentation is to count the number of times each jump
// table entry is dereferenced. To do this we redirect each reference in the
// jump tables to the following hook:
//     push unique_id_for_this_case
//     call jump_table_count.dll!_jump_table_case_counter
//     jmp original_reference

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_JUMP_TABLE_COUNT_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_JUMP_TABLE_COUNT_TRANSFORM_H_

#include <string>
#include <utility>
#include <vector>

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/instrument/transforms/add_indexed_frequency_data_transform.h"

namespace instrument {
namespace transforms {

// An iterative transform that instruments the accesses to the jump/case tables
// to measure the frequency of each case.
class JumpTableCaseCountTransform
    : public block_graph::transforms::IterativeTransformImpl<
          JumpTableCaseCountTransform> {
 public:
  // Initialize a new JumpTableCaseCountTransform instance using the default
  // module and function names.
  JumpTableCaseCountTransform();

 protected:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // @name Accessors. For testing.
  // @{
  const BlockGraph::Section* thunk_section() const { return thunk_section_; }
  AddIndexedFrequencyDataTransform* add_frequency_data() {
    return &add_frequency_data_;
  }
  BlockGraph::Reference* jump_table_case_counter_hook_ref() {
    return &jump_table_case_counter_hook_ref_;
  }
  // @}

 private:
  friend NamedBlockGraphTransformImpl<JumpTableCaseCountTransform>;
  friend IterativeTransformImpl<JumpTableCaseCountTransform>;

  typedef core::RelativeAddress RelativeAddress;
  // A pair containing the address of a jump-table and its size.
  typedef std::pair<RelativeAddress, size_t> JumpTableInfo;
  typedef std::vector<JumpTableInfo> JumpTableVector;

  // The name of this transform.
  static const char kTransformName[];

  // @name IterativeTransformImpl implementation.
  // @{
  bool PreBlockGraphIteration(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);
  bool PostBlockGraphIteration(const TransformPolicyInterface* policy,
                               BlockGraph* block_graph,
                               BlockGraph::Block* header_block);
  // @}

  // Creates a single thunk to destination.
  // @param block_graph the block-graph being instrumented.
  // @param destination the destination reference.
  // @returns a pointer to the thunk on success, NULL otherwise.
  BlockGraph::Block* CreateOneThunk(BlockGraph* block_graph,
                                    const BlockGraph::Reference& destination);

  // The section we put our thunks in.
  BlockGraph::Section* thunk_section_;

  // Adds the jump table frequency data referenced by the jump-table
  // instrumentation.
  AddIndexedFrequencyDataTransform add_frequency_data_;

  // The entry hook to which jump table entry events are directed.
  BlockGraph::Reference jump_table_case_counter_hook_ref_;

  // The instrumentation dll used by this transform.
  std::string instrument_dll_name_;

  // The counter used to get a unique ID for each case in a jump table.
  size_t jump_table_case_count_;

  // The different jump tables encountered; we store their addresses and sizes.
  JumpTableVector jump_table_infos_;

  DISALLOW_COPY_AND_ASSIGN(JumpTableCaseCountTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_JUMP_TABLE_COUNT_TRANSFORM_H_
