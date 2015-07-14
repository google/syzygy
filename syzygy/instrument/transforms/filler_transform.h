// Copyright 2015 Google Inc. All Rights Reserved.
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
// Declaration of the filler instrumentation transform. This instruments a given
// list of functions by injecting NOP fillers at various places.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_FILLER_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_FILLER_TRANSFORM_H_

#include <map>
#include <set>
#include <string>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"

using block_graph::TransformPolicyInterface;

namespace instrument {
namespace transforms {

// A class to transform subgraph by injecting NOP fillers to basic code blocks.
class FillerBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          FillerBasicBlockTransform> {
 public:
  typedef block_graph::BasicBlock BasicBlock;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef BlockGraph::Block Block;

  // NOP sizes that can be realized with a single instruction. We disallow
  // multi-instruction NOPs to ensure consistent instruction indexes after NOP
  // injection.
  enum NopSizes {
    NOP1 = 1,
    NOP2,
    NOP3,
    NOP4,
    NOP5,
    NOP6,
    NOP7,
    NOP8,
    NOP9,
    NOP10,
    NOP11,
  };

  // A map from instruction indices to NOP sizes. For example,
  // {1: NOP3, 3: NOP2, 4: NOP5} specifies a transformation that takes
  // instruction sequence "ABCDE" to "AXBYZCDE", where "X" is the 3-byte NOP,
  // "Y" is the 2-byte NOP, and "Z" is the 5-byte NOP.
  typedef std::map<size_t, NopSizes> NopSpec;

  FillerBasicBlockTransform()
      : debug_friendly_(false) { }
  virtual ~FillerBasicBlockTransform() { }

  // For NamedBlockGraphTransformImpl.
  static const char kTransformName[];

  // @name Accessors and mutators.
  // @{
  bool debug_friendly() const { return debug_friendly_; }
  void set_debug_friendly(bool flag) { debug_friendly_ = flag; }
  // @}

  // Injects NOP into @p instruction. @p nop_spec specifies post-injection
  // instruction indices and sizes of NOPs. We do not inject beyond the last
  // instruction.
  static void InjectNop(const NopSpec& nop_spec,
                        bool debug_friendly,
                        BasicBlock::Instructions* instructions);

  // @name BasicBlockSubGraphTransformInterface implementation.
  // @{
  // Applies the filler transform. Specifically, visits every basic code block
  // in @p basic_block_subgraph and injects NOP at various places.
  bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) override;
  // @}

 private:
  // Activate the overwriting of source range for created instructions.
  bool debug_friendly_;

  DISALLOW_COPY_AND_ASSIGN(FillerBasicBlockTransform);
};

// A class to apply filler transform, which injects NOPs to basic code blocks
// in a given list of decorated function names.
class FillerTransform
    : public block_graph::transforms::IterativeTransformImpl<FillerTransform> {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef BlockGraph::Block Block;

  FillerTransform(const std::set<std::string>& target_set, bool add_copy);
  virtual ~FillerTransform() { }

  // Accessors
  // @{
  size_t num_targets_updated() const { return num_targets_updated_; }
  // @}

  // For NamedBlockGraphTransformImpl.
  static const char kTransformName[];

  // @name Accessors and mutators.
  // @{
  bool debug_friendly() const { return debug_friendly_; }
  void set_debug_friendly(bool flag) { debug_friendly_ = flag; }
  const std::map<std::string, bool>& target_visited() const {
    return target_visited_;
  }
  // @}

 protected:
  // Returns whether @p block is a target.
  bool ShouldProcessBlock(Block* block) const;

  // Verifies that all targets were found, and displays warning if not.
  void CheckAllTargetsFound() const;

  // @name IterativeTransformImpl implementation.
  // @{
  bool PreBlockGraphIteration(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              Block* header_block);
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               Block* block);
  bool PostBlockGraphIteration(const TransformPolicyInterface* policy,
                               BlockGraph* block_graph,
                               Block* header_block);
  // @}

 private:
  friend NamedBlockGraphTransformImpl<FillerTransform>;
  friend IterativeTransformImpl<FillerTransform>;

  // Activate the overwriting of source range for created instructions.
  bool debug_friendly_;

  // Whether to add a dummy copy of each target.
  bool add_copy_;

  // Maps from target names to whether a block with given name was visited.
  std::map<std::string, bool> target_visited_;

  // Counters used by CheckAllTargetsFound.
  // @{
  size_t num_blocks_;
  size_t num_code_blocks_;
  size_t num_targets_updated_;
  // @}

  DISALLOW_COPY_AND_ASSIGN(FillerTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_FILLER_TRANSFORM_H_
