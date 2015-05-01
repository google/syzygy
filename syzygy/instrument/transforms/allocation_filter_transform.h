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
// Allocation-filter instrumentation transform.
// This is an extension of the Asan transform that allows enabling/disabling
// heavy allocation instrumentation at targeted allocation sites.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ALLOCATION_FILTER_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ALLOCATION_FILTER_TRANSFORM_H_

#include <map>
#include <set>
#include <string>
#include <vector>

#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/instrument/transforms/asan_transform.h"

namespace instrument {
namespace transforms {

// An iterative block transformation that augments the binary with imports for
// pre-call/post-call hook functions and, for each targeted call instruction,
// prepends and appends a call to the hook functions. The hook functions are
// responsible for being non-disruptive to the calling environment.
// I.e., they must preserve all volatile registers, any registers they use, and
// the processor flags, the post-call hook function should preserve the original
// return value .
class AllocationFilterTransform
    : public block_graph::transforms::IterativeTransformImpl<
          AllocationFilterTransform>,
      public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          AllocationFilterTransform> {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::Instruction::Offset Offset;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef std::set<Offset> OffsetSet;
  typedef std::map<std::string, OffsetSet> FunctionNameOffsetMap;

  // Initialize a new AllocationFilterTransform instance with the target
  // addresses to hook.
  // @params targets For each target function name, stores a set of offsets of
  //     the (call) instructions to hook.
  explicit AllocationFilterTransform(FunctionNameOffsetMap targets);

  // Overrides the default instrument dll name used by this transform.
  void set_instrument_dll_name(const base::StringPiece& value) {
    DCHECK(!value.empty());
    instrument_dll_name_.assign(value.begin(), value.end());
  }

  bool debug_friendly() const { return debug_friendly_; }
  void set_debug_friendly(bool flag) { debug_friendly_ = flag; }

  bool enable_reporting() const { return enable_reporting_; }
  void set_enable_reporting(bool flag) { enable_reporting_ = flag; }

  // Loads (from a JSON string) target call addresses which are represented
  // by a function name and an offset.
  // The contents of the 'json' string should follow the following format:
  // {
  //   "hooks": {
  //     "function_name1": [offset1_1, offset1_2, ...],
  //     "function_name2": [offset2_1, offset2_2, ...],
  //     "function_name3": [offset3_1, offset3_2, ...],
  //     ...
  //   }
  // }
  // All offsets are represented as integers and should point to the instruction
  // following the one that we want to target, as it's usually represented in
  // the stack traces.
  // @param json A JSON string containing the target addresses following the
  //     format described above.
  // @param path Path to a JSON file, to use a file instead of a string.
  // @param targets Output parameter, all the target calls extracted from the
  //     JSON string will be dumped to |targets|.
  // @returns True if the operation succeeded, false otherwise.
  // @note The |targets| map could be modified or partially filled in the case
  //     of an error.
  static bool AllocationFilterTransform::ReadFromJSON(
      const std::string& json,
      FunctionNameOffsetMap* targets);
  static bool AllocationFilterTransform::ReadFromJSON(
      const base::FilePath& path,
      FunctionNameOffsetMap* targets);

 protected:
  friend NamedBlockGraphTransformImpl<AllocationFilterTransform>;
  friend IterativeTransformImpl<AllocationFilterTransform>;
  friend NamedBasicBlockSubGraphTransformImpl<AllocationFilterTransform>;

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
      BasicBlockSubGraph* basic_block_subgraph) override;
  // @}

  // The pre-call hook which is called before hooked calls.
  BlockGraph::Reference pre_call_hook_ref_;

  // The post-call hook which is called after hooked calls.
  BlockGraph::Reference post_call_hook_ref_;

  // The instrumentation dll used by this transform.
  std::string instrument_dll_name_;

  // The name of this transform.
  static const char kTransformName[];

  // Activate the overwriting of source range for created instructions.
  bool debug_friendly_;

  // Enables/disables the reporting of non-instrumented targets.
  // Reporting is enabled by default.
  // This only enables/disables logging (which can be very slow); instrumented
  // calls are still tracked.
  bool enable_reporting_;

  // For each function name, stores the set of 'call' instruction offsets to be
  // hooked. The offset should point to the instruction following the one to
  // hook.
  FunctionNameOffsetMap targets_;

  // Instrumented calls bookkeeping.
  FunctionNameOffsetMap instrumented_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AllocationFilterTransform);
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ALLOCATION_FILTER_TRANSFORM_H_
