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
// Implementation of the basic-block entry hook instrumentation transform.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_BASIC_BLOCK_ENTRY_HOOK_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_BASIC_BLOCK_ENTRY_HOOK_TRANSFORM_H_

#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/instrument/transforms/add_indexed_frequency_data_transform.h"

namespace instrument {
namespace transforms {

// An iterative block transformation that augments the binary with an import
// for a basic-block entry-hook function and, for each code basic-block,
// prepends a call to the entry-hook function taking a unique basic-block ID.
// The entry-hook function is responsible for being non-disruptive to the
// calling environment. I.e., it must preserve all volatile registers, any
// registers it uses, and the processor flags.
class BasicBlockEntryHookTransform
    : public block_graph::transforms::IterativeTransformImpl<
          BasicBlockEntryHookTransform>,
      public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          BasicBlockEntryHookTransform> {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef core::RelativeAddress RelativeAddress;
  typedef core::AddressRange<RelativeAddress, size_t> RelativeAddressRange;
  typedef std::vector<RelativeAddressRange> RelativeAddressRangeVector;

  // Initialize a new BasicBlockEntryHookTransform instance using the default
  // module and function names.
  BasicBlockEntryHookTransform();

  // @returns the RVAs and sizes in the original image of the instrumented basic
  //    blocks. They are in the order in which they were encountered during
  //    instrumentation, such that the index of the BB in the vector serves
  //    as its unique ID.
  const RelativeAddressRangeVector& bb_ranges() const { return bb_ranges_; }

  // Overrides the default instrument dll name used by this transform.
  void set_instrument_dll_name(const base::StringPiece& value) {
    DCHECK(!value.empty());
    instrument_dll_name_.assign(value.begin(), value.end());
  }

  // Set a flag denoting whether or not src ranges should be created for the
  // thunks to the module entry hooks.
  void set_src_ranges_for_thunks(bool value) {
    set_src_ranges_for_thunks_ = value;
  }

  // Returns a flag denoting whether or not the instrumented application should
  // call the fast-path hook.
  bool inline_fast_path() { return set_inline_fast_path_; }

  // Set a flag denoting whether or not the instrumented application should
  // call the fast-path hook.
  void set_inline_fast_path(bool value) {
    set_inline_fast_path_ = value;
  }

 protected:
  typedef std::map<BlockGraph::Offset, BlockGraph::Block*> ThunkBlockMap;

  friend NamedBlockGraphTransformImpl<BasicBlockEntryHookTransform>;
  friend IterativeTransformImpl<BasicBlockEntryHookTransform>;
  friend NamedBasicBlockSubGraphTransformImpl<BasicBlockEntryHookTransform>;

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

  // @name BasicBlockSubGraphTransformInterface implementation.
  // @{
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) OVERRIDE;
  // @}

  // Add basic-block entry counting thunks for all entry points of a
  // @p code_block which is not basic-block decomposable.
  // @param block_graph The block graph in which to create the thunk.
  // @param code_block The code block which cannot be basic-block decomposed.
  // @returns true on success; false otherwise.
  bool ThunkNonDecomposableCodeBlock(BlockGraph* block_graph,
                                     BlockGraph::Block* code_block);

  // Redirects the given referrer to a thunk, creating the thunk if necessary.
  // @param referrer The details of the original referrer.
  // @param block_graph The block graph in which to create the thunk.
  // @param code_block The target block being thunked.
  // @param thunk_block_map A map (by target offset) of the thunks already
  //     created. We only create a single thunk per target offset, which is
  //     reused across referrers to the same target offset.
  // @returns true on success; false otherwise.
  bool EnsureReferrerIsThunked(const BlockGraph::Block::Referrer& referrer,
                               BlockGraph* block_graph,
                               BlockGraph::Block* block,
                               ThunkBlockMap* thunk_block_map);

  // Add a basic-block entry counting thunk for an entry point at a given
  // @p offset of a @p code_block which is unsuitable for basic-block
  // decomposition.
  // @param block_graph The block graph in which to create the thunk.
  // @param thunk_block_map A catalog of thunk blocks created by this transform.
  //     This will be updated if this function creates a new think.
  // @param code_block The code block which cannot be basic-block decomposed.
  // @param offset The offset of the entry point in @p code_block to thunk.
  // @param thunk The newly created thunk will be returned here.
  // @returns true on success; false otherwise.
  bool FindOrCreateThunk(BlockGraph* block_graph,
                         ThunkBlockMap* thunk_block_map,
                         BlockGraph::Block* code_block,
                         BlockGraph::Offset offset,
                         BlockGraph::Block** thunk);

  // Create a fast path thunk in the instrumented application which updates the
  // basic block count or calls the hook in the agent.
  // @param block_graph The block graph in which to create the thunk.
  // @param fast_path_block On success, contains the newly created thunk.
  // @returns true on success; false otherwise.
  bool CreateBasicBlockEntryThunk(BlockGraph* block_graph,
                                  BlockGraph::Block** fast_path_block);

  // Adds the basic-block frequency data referenced by the coverage agent.
  AddIndexedFrequencyDataTransform add_frequency_data_;

  // Stores the RVAs in the original image for each instrumented basic block.
  RelativeAddressRangeVector bb_ranges_;

  // The entry hook to which basic-block entry events are directed.
  BlockGraph::Reference bb_entry_hook_ref_;

  // The section where the entry-point thunks were placed. This will only be
  // non-NULL after a successful application of the transform. This value is
  // retained for unit-testing purposes.
  BlockGraph::Section* thunk_section_;

  // The instrumentation dll used by this transform.
  std::string instrument_dll_name_;

  // If true, the thunks will have src ranges corresponding to the original
  // code; otherwise, the thunks will not have src ranges set.
  bool set_src_ranges_for_thunks_;

  // If true, the instrumented application calls a fast injected hook before
  // falling back to the hook in the agent.
  bool set_inline_fast_path_;

  // The name of this transform.
  static const char kTransformName[];

 private:
  DISALLOW_COPY_AND_ASSIGN(BasicBlockEntryHookTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_BASIC_BLOCK_ENTRY_HOOK_TRANSFORM_H_
