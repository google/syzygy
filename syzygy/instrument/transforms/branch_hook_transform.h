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
// Implementation of the branch instrumentation transform.
#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_BRANCH_HOOK_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_BRANCH_HOOK_TRANSFORM_H_

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

// An iterative block transformation that augments the binary with imports for
// basic-block entry/exit-hook function and, for each code basic-block, insert a
// call to the hook functions taking a unique basic-block ID. The hook functions
// are responsible for being non-disruptive to the calling environment.
// I.e., they must preserve all volatile registers, any registers they use, and
// the processor flags.
class BranchHookTransform
    : public block_graph::transforms::IterativeTransformImpl<
          BranchHookTransform>,
      public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          BranchHookTransform> {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef core::RelativeAddress RelativeAddress;
  typedef core::AddressRange<RelativeAddress, size_t> RelativeAddressRange;
  typedef std::vector<RelativeAddressRange> RelativeAddressRangeVector;

  // Initialize a new BranchHookTransform instance using the default module and
  // function names.
  BranchHookTransform();

  // @returns the RVAs and sizes in the original image of the instrumented basic
  //    blocks. They are in the order in which they were encountered during
  //    instrumentation, such that the index of the BB in the vector serves as
  //    its unique ID.
  const RelativeAddressRangeVector& bb_ranges() const { return bb_ranges_; }

  // Overrides the default instrument dll name used by this transform.
  void set_instrument_dll_name(const base::StringPiece& value) {
    DCHECK(!value.empty());
    instrument_dll_name_.assign(value.begin(), value.end());
  }

  // @name Accessors and mutators.
  // @{
  bool buffering() const { return buffering_; }
  void set_buffering(bool buffering) { buffering_ = buffering; }
  void set_fs_slot(uint32 slot) { fs_slot_ = slot; }
  // @}

 protected:
  friend NamedBlockGraphTransformImpl<BranchHookTransform>;
  friend IterativeTransformImpl<BranchHookTransform>;
  friend NamedBasicBlockSubGraphTransformImpl<BranchHookTransform>;

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

  // Adds the basic-block frequency data referenced by the coverage agent.
  AddIndexedFrequencyDataTransform add_frequency_data_;

  // Stores the RVAs in the original image for each instrumented basic block.
  RelativeAddressRangeVector bb_ranges_;

  // The entry hook to which function entry events are directed.
  BlockGraph::Reference function_enter_hook_ref_;

  // The entry hook to which basic-block entry events are directed.
  BlockGraph::Reference enter_hook_ref_;

  // The entry hook to which basic-block exit events are directed.
  BlockGraph::Reference exit_hook_ref_;

  // The section where the entry-point thunks were placed. This will only be
  // non-NULL after a successful application of the transform. This value is
  // retained for unit-testing purposes.
  BlockGraph::Section* thunk_section_;

  // The instrumentation dll used by this transform.
  std::string instrument_dll_name_;

  // The name of this transform.
  static const char kTransformName[];

  // Flag indicating if event buffering is activated.
  bool buffering_;

  // If not zero, use a FS slot to keep thread local storage instead of the
  // standard API.
  uint32 fs_slot_;

 private:
  DISALLOW_COPY_AND_ASSIGN(BranchHookTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_BRANCH_HOOK_TRANSFORM_H_
